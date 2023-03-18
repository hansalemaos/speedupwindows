@echo off
:: Ensure admin privileges
fltmc >nul 2>&1 || (
    echo Administrator privileges are required.
    PowerShell Start -Verb RunAs '%0' 2> nul || (
        echo Right-click on the script and select "Run as administrator".
        pause & exit 1
    )
    exit 0
)


:: ----------------------------------------------------------
:: ------------------Clear thumbnail cache-------------------
:: ----------------------------------------------------------
echo --- Clear thumbnail cache
del /f /s /q /a %LocalAppData%\Microsoft\Windows\Explorer\*.db
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------Clear Windows temp files-----------------
:: ----------------------------------------------------------
echo --- Clear Windows temp files
del /f /q %localappdata%\Temp\*
rd /s /q "%WINDIR%\Temp"
rd /s /q "%TEMP%"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Clear main telemetry file-----------------
:: ----------------------------------------------------------
echo --- Clear main telemetry file
if exist "%ProgramData%\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl" (
    takeown /f "%ProgramData%\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl" /r /d y
    icacls "%ProgramData%\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl" /grant administrators:F /t
    echo "" > "%ProgramData%\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl"
    echo Clear successful: "%ProgramData%\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl"
) else (
    echo "Main telemetry file does not exist. Good!"
)
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Clear Event Logs in Event Viewer-------------
:: ----------------------------------------------------------
echo --- Clear Event Logs in Event Viewer
REM https://social.technet.microsoft.com/Forums/en-US/f6788f7d-7d04-41f1-a64e-3af9f700e4bd/failed-to-clear-log-microsoftwindowsliveidoperational-access-is-denied?forum=win10itprogeneral
wevtutil sl Microsoft-Windows-LiveId/Operational /ca:O:BAG:SYD:(A;;0x1;;;SY)(A;;0x5;;;BA)(A;;0x1;;;LA)
for /f "tokens=*" %%i in ('wevtutil.exe el') DO (
    echo Deleting event log: "%%i"
    wevtutil.exe cl %1 "%%i"
)
:: ----------------------------------------------------------

:: ----------------------------------------------------------
:: Clear Optional Component Manager and COM+ components logs-
:: ----------------------------------------------------------
echo --- Clear Optional Component Manager and COM+ components logs
del /f /q %SystemRoot%\comsetup.log
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------Clear Distributed Transaction Coordinator logs------
:: ----------------------------------------------------------
echo --- Clear Distributed Transaction Coordinator logs
del /f /q %SystemRoot%\DtcInstall.log
:: ----------------------------------------------------------

echo disable animation
REG ADD "HKEY_CURRENT_USER\Control Panel\Desktop\WindowMetrics" /v MinAnimate /t REG_SZ /d 0 /f >nul 2>&1

:: ----------------------------------------------------------
:: --------Clear Pending File Rename Operations logs---------
:: ----------------------------------------------------------
echo --- Clear Pending File Rename Operations logs
del /f /q %SystemRoot%\PFRO.log
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------Clear Windows Deployment Upgrade Process Logs-------
:: ----------------------------------------------------------
echo --- Clear Windows Deployment Upgrade Process Logs
del /f /q %SystemRoot%\setupact.log
del /f /q %SystemRoot%\setuperr.log
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------Clear Windows Setup Logs-----------------
:: ----------------------------------------------------------
echo --- Clear Windows Setup Logs
del /f /q %SystemRoot%\setupapi.log
del /f /q %SystemRoot%\Panther\*
del /f /q %SystemRoot%\inf\setupapi.app.log
del /f /q %SystemRoot%\inf\setupapi.dev.log
del /f /q %SystemRoot%\inf\setupapi.offline.log
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Clear Windows System Assessment Tool logs---------
:: ----------------------------------------------------------
echo --- Clear Windows System Assessment Tool logs
del /f /q %SystemRoot%\Performance\WinSAT\winsat.log
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Clear Password change events---------------
:: ----------------------------------------------------------
echo --- Clear Password change events
del /f /q %SystemRoot%\debug\PASSWD.LOG
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Clear user web cache database---------------
:: ----------------------------------------------------------
echo --- Clear user web cache database
del /f /q %localappdata%\Microsoft\Windows\WebCache\*.*
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----Clear system temp folder when no one is logged in-----
:: ----------------------------------------------------------
echo --- Clear system temp folder when no one is logged in
del /f /q %SystemRoot%\ServiceProfiles\LocalService\AppData\Local\Temp\*.*
:: ----------------------------------------------------------


:: Clear DISM (Deployment Image Servicing and Management) Logs
echo --- Clear DISM (Deployment Image Servicing and Management) Logs
del /f /q  %SystemRoot%\Logs\CBS\CBS.log
del /f /q  %SystemRoot%\Logs\DISM\DISM.log
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Clear WUAgent (Windows Update History) logs--------
:: ----------------------------------------------------------
echo --- Clear WUAgent (Windows Update History) logs
setlocal EnableDelayedExpansion 
    SET /A wuau_service_running=0
    SC queryex "wuauserv"|Find "STATE"|Find /v "RUNNING">Nul||(
        SET /A wuau_service_running=1
        net stop wuauserv
    )
    del /q /s /f "%SystemRoot%\SoftwareDistribution"
    IF !wuau_service_running! == 1 (
        net start wuauserv
    )
endlocal
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Clear Server-initiated Healing Events Logs--------
:: ----------------------------------------------------------
echo --- Clear Server-initiated Healing Events Logs
del /f /q "%SystemRoot%\Logs\SIH\*"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Common Language Runtime Logs---------------
:: ----------------------------------------------------------
echo --- Common Language Runtime Logs
del /f /q "%LocalAppData%\Microsoft\CLR_v4.0\UsageTraces\*"
del /f /q "%LocalAppData%\Microsoft\CLR_v4.0_32\UsageTraces\*"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Network Setup Service Events Logs-------------
:: ----------------------------------------------------------
echo --- Network Setup Service Events Logs
del /f /q "%SystemRoot%\Logs\NetSetup\*"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Disk Cleanup tool (Cleanmgr.exe) Logs-----------
:: ----------------------------------------------------------
echo --- Disk Cleanup tool (Cleanmgr.exe) Logs
del /f /q "%SystemRoot%\System32\LogFiles\setupcln\*"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Clear Windows update and SFC scan logs----------
:: ----------------------------------------------------------
echo --- Clear Windows update and SFC scan logs
del /f /q %SystemRoot%\Temp\CBS\*
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Clear Windows Update Medic Service logs----------
:: ----------------------------------------------------------
echo --- Clear Windows Update Medic Service logs
takeown /f %SystemRoot%\Logs\waasmedic /r /d y
icacls %SystemRoot%\Logs\waasmedic /grant administrators:F /t
rd /s /q %SystemRoot%\Logs\waasmedic
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Clear Cryptographic Services Traces------------
:: ----------------------------------------------------------
echo --- Clear Cryptographic Services Traces
del /f /q %SystemRoot%\System32\catroot2\dberr.txt
del /f /q %SystemRoot%\System32\catroot2.log
del /f /q %SystemRoot%\System32\catroot2.jrs
del /f /q %SystemRoot%\System32\catroot2.edb
del /f /q %SystemRoot%\System32\catroot2.chk
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Windows Update Events Logs----------------
:: ----------------------------------------------------------
echo --- Windows Update Events Logs
del /f /q "%SystemRoot%\Logs\SIH\*"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------Windows Update Logs--------------------
:: ----------------------------------------------------------
echo --- Windows Update Logs
del /f /q "%SystemRoot%\Traces\WindowsUpdate\*"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Delete controversial default0 user------------
:: ----------------------------------------------------------
echo --- Delete controversial default0 user
net user defaultuser0 /delete 2>nul
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Clear previous Windows installations-----------
:: ----------------------------------------------------------
echo --- Clear previous Windows installations
if exist "%SystemDrive%\Windows.old" (
    takeown /f "%SystemDrive%\Windows.old" /a /r /d y
    icacls "%SystemDrive%\Windows.old" /grant administrators:F /t
    rd /s /q "%SystemDrive%\Windows.old"
    echo Deleted previous installation from "%SystemDrive%\Windows.old\"
)  else (
    echo No previous Windows installation has been found
)
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----Disable Customer Experience Improvement (CEIP/SQM)----
:: ----------------------------------------------------------
echo --- Disable Customer Experience Improvement (CEIP/SQM)
reg add "HKLM\Software\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Disable Application Impact Telemetry (AIT)--------
:: ----------------------------------------------------------
echo --- Disable Application Impact Telemetry (AIT)
reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d "0" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----Disable Customer Experience Improvement Program------
:: ----------------------------------------------------------
echo --- Disable Customer Experience Improvement Program
schtasks /change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /DISABLE
schtasks /change /TN "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /DISABLE
schtasks /change /TN "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /DISABLE
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Disable telemetry in data collection policy--------
:: ----------------------------------------------------------
echo --- Disable telemetry in data collection policy
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /d 0 /t REG_DWORD /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "LimitEnhancedDiagnosticDataWindowsAnalytics" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f 
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Disable license telemetry-----------------
:: ----------------------------------------------------------
echo --- Disable license telemetry
reg add "HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v "NoGenTicket" /t "REG_DWORD" /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------Disable error reporting------------------
:: ----------------------------------------------------------
echo --- Disable error reporting
:: Disable Windows Error Reporting (WER)
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t "REG_DWORD" /d "1" /f
:: DefaultConsent / 1 - Always ask (default) / 2 - Parameters only / 3 - Parameters and safe data / 4 - All data
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultConsent" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultOverrideBehavior" /t REG_DWORD /d "1" /f
:: Disable WER sending second-level data
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f
:: Disable WER crash dialogs, popups
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "LoggingDisabled" /t REG_DWORD /d "1" /f
schtasks /Change /TN "Microsoft\Windows\ErrorDetails\EnableErrorDetailsUpdate" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'wersvc'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) {; Write-Host "^""Service `"^""$serviceName`"^"" could not be not found, no need to disable it."^""; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try {; Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else {; Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if(!$startupType) {; $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) {; $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if($startupType -eq 'Disabled') {; Write-Host "^""$serviceName is already disabled, no further action is needed"^""; }; <# -- 4. Disable service #>; try {; Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'wercplsupport'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) {; Write-Host "^""Service `"^""$serviceName`"^"" could not be not found, no need to disable it."^""; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try {; Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else {; Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if(!$startupType) {; $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) {; $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if($startupType -eq 'Disabled') {; Write-Host "^""$serviceName is already disabled, no further action is needed"^""; }; <# -- 4. Disable service #>; try {; Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -Disable connected user experiences and telemetry service-
:: ----------------------------------------------------------
echo --- Disable connected user experiences and telemetry service
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'DiagTrack'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) {; Write-Host "^""Service `"^""$serviceName`"^"" could not be not found, no need to disable it."^""; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try {; Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else {; Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if(!$startupType) {; $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) {; $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if($startupType -eq 'Disabled') {; Write-Host "^""$serviceName is already disabled, no further action is needed"^""; }; <# -- 4. Disable service #>; try {; Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Disable WAP push message routing service---------
:: ----------------------------------------------------------
echo --- Disable WAP push message routing service
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'dmwappushservice'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) {; Write-Host "^""Service `"^""$serviceName`"^"" could not be not found, no need to disable it."^""; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try {; Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else {; Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if(!$startupType) {; $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) {; $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if($startupType -eq 'Disabled') {; Write-Host "^""$serviceName is already disabled, no further action is needed"^""; }; <# -- 4. Disable service #>; try {; Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----Disable diagnostics hub standard collector service----
:: ----------------------------------------------------------
echo --- Disable diagnostics hub standard collector service
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'diagnosticshub.standardcollector.service'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) {; Write-Host "^""Service `"^""$serviceName`"^"" could not be not found, no need to disable it."^""; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try {; Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else {; Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if(!$startupType) {; $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) {; $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if($startupType -eq 'Disabled') {; Write-Host "^""$serviceName is already disabled, no further action is needed"^""; }; <# -- 4. Disable service #>; try {; Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Disable diagnostic execution service-----------
:: ----------------------------------------------------------
echo --- Disable diagnostic execution service
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'diagsvc'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) {; Write-Host "^""Service `"^""$serviceName`"^"" could not be not found, no need to disable it."^""; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try {; Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else {; Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if(!$startupType) {; $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) {; $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if($startupType -eq 'Disabled') {; Write-Host "^""$serviceName is already disabled, no further action is needed"^""; }; <# -- 4. Disable service #>; try {; Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Disable devicecensus.exe (telemetry) task---------
:: ----------------------------------------------------------
echo --- Disable devicecensus.exe (telemetry) task
schtasks /change /TN "Microsoft\Windows\Device Information\Device" /disable
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Disable devicecensus.exe (telemetry) process-------
:: ----------------------------------------------------------
echo --- Disable devicecensus.exe (telemetry) process
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\'DeviceCensus.exe'" /v "Debugger" /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
:: ----------------------------------------------------------


:: Disable sending information to Customer Experience Improvement Program
echo --- Disable sending information to Customer Experience Improvement Program
schtasks /change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /disable
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----Disable Application Impact Telemetry Agent task------
:: ----------------------------------------------------------
echo --- Disable Application Impact Telemetry Agent task
schtasks /change /TN "Microsoft\Windows\Application Experience\AitAgent" /disable
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --Disable "Disable apps to improve performance" reminder--
:: ----------------------------------------------------------
echo --- Disable "Disable apps to improve performance" reminder
schtasks /change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /disable
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------Disable Microsoft Compatibility Appraiser task------
:: ----------------------------------------------------------
echo --- Disable Microsoft Compatibility Appraiser task
schtasks /change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /disable
:: ----------------------------------------------------------


:: Disable CompatTelRunner.exe (Microsoft Compatibility Appraiser) process
echo --- Disable CompatTelRunner.exe (Microsoft Compatibility Appraiser) process
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\'CompatTelRunner.exe'" /v "Debugger" /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -Disable device metadata retrieval (breaks auto updates)--
:: ----------------------------------------------------------
echo --- Disable device metadata retrieval (breaks auto updates)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Do not include drivers with Windows Updates--------
:: ----------------------------------------------------------
echo --- Do not include drivers with Windows Updates
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----Prevent Windows Update for device driver search------
:: ----------------------------------------------------------
echo --- Prevent Windows Update for device driver search
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v "SearchOrderConfig" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Turn off Windows Location Provider------------
:: ----------------------------------------------------------
echo --- Turn off Windows Location Provider
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Turn off location scripting----------------
:: ----------------------------------------------------------
echo --- Turn off location scripting
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------------Turn off location---------------------
:: ----------------------------------------------------------
echo --- Turn off location
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /d "1" /t REG_DWORD /f
:: For older Windows (before 1903)
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "SensorPermissionState" /d "0" /t REG_DWORD /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "Value" /t REG_SZ /d "Deny" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Do not allow search to use location------------
:: ----------------------------------------------------------
echo --- Do not allow search to use location
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Disable web search in search bar-------------
:: ----------------------------------------------------------
echo --- Disable web search in search bar
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --Do not search the web or display web results in Search--
:: ----------------------------------------------------------
echo --- Do not search the web or display web results in Search
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------Disable Bing search--------------------
:: ----------------------------------------------------------
echo --- Disable Bing search
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------Do not allow Cortana-------------------
:: ----------------------------------------------------------
echo --- Do not allow Cortana
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Do not allow Cortana experience--------------
:: ----------------------------------------------------------
echo --- Do not allow Cortana experience
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana" /v "value" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: Do not allow search and Cortana to search cloud sources like OneDrive and SharePoint
echo --- Do not allow search and Cortana to search cloud sources like OneDrive and SharePoint
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: Disable Cortana speech interaction while the system is locked
echo --- Disable Cortana speech interaction while the system is locked
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortanaAboveLock" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Opt out from Cortana consent---------------
:: ----------------------------------------------------------
echo --- Opt out from Cortana consent
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaConsent" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Do not allow Cortana to be enabled------------
:: ----------------------------------------------------------
echo --- Do not allow Cortana to be enabled
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CanCortanaBeEnabled" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -Disable Cortana (Internet search results in start menu)--
:: ----------------------------------------------------------
echo --- Disable Cortana (Internet search results in start menu)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d 0 /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d 0 /f 
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Remove the Cortana taskbar icon--------------
:: ----------------------------------------------------------
echo --- Remove the Cortana taskbar icon
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v "ShowCortanaButton" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Disable Cortana in ambient mode--------------
:: ----------------------------------------------------------
echo --- Disable Cortana in ambient mode
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaInAmbientMode" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Prevent Cortana from displaying history----------
:: ----------------------------------------------------------
echo --- Prevent Cortana from displaying history
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "HistoryViewEnabled" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Prevent Cortana from using device history---------
:: ----------------------------------------------------------
echo --- Prevent Cortana from using device history
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "DeviceHistoryEnabled" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Disable "Hey Cortana" voice activation----------
:: ----------------------------------------------------------
echo --- Disable "Hey Cortana" voice activation
reg add "HKCU\Software\Microsoft\Speech_OneCore\Preferences" /v "VoiceActivationOn" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\Speech_OneCore\Preferences" /v "VoiceActivationDefaultOn" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -Disable Cortana listening to commands on Windows key + C-
:: ----------------------------------------------------------
echo --- Disable Cortana listening to commands on Windows key + C
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "VoiceShortcut" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----Disable using Cortana even when device is locked-----
:: ----------------------------------------------------------
echo --- Disable using Cortana even when device is locked
reg add "HKCU\Software\Microsoft\Speech_OneCore\Preferences" /v "VoiceActivationEnableAboveLockscreen" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Disable automatic update of Speech Data----------
:: ----------------------------------------------------------
echo --- Disable automatic update of Speech Data
reg add "HKCU\Software\Microsoft\Speech_OneCore\Preferences" /v "ModelDownloadAllowed" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----Disable Cortana voice support during Windows setup----
:: ----------------------------------------------------------
echo --- Disable Cortana voice support during Windows setup
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" /v "DisableVoice" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----Disable search indexing encrypted items / stores-----
:: ----------------------------------------------------------
echo --- Disable search indexing encrypted items / stores
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowIndexingEncryptedStoresOrItems" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --Do not use automatic language detection when indexing---
:: ----------------------------------------------------------
echo --- Do not use automatic language detection when indexing
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AlwaysUseAutoLangDetection" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Disable ad customization with Advertising ID-------
:: ----------------------------------------------------------
echo --- Disable ad customization with Advertising ID
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Turn Off Suggested Content in Settings app--------
:: ----------------------------------------------------------
echo --- Turn Off Suggested Content in Settings app
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /d "0" /t REG_DWORD /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /d "0" /t REG_DWORD /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /d "0" /t REG_DWORD /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------Disable Windows Tips-------------------
:: ----------------------------------------------------------
echo --- Disable Windows Tips
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableSoftLanding" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: Disable Windows Spotlight (random wallpaper on lock screen)
echo --- Disable Windows Spotlight (random wallpaper on lock screen)
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightFeatures" /t "REG_DWORD" /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Disable Microsoft consumer experiences----------
:: ----------------------------------------------------------
echo --- Disable Microsoft consumer experiences
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t "REG_DWORD" /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Do not allow the use of biometrics------------
:: ----------------------------------------------------------
echo --- Do not allow the use of biometrics
reg add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics" /v "Enabled" /t REG_DWORD /d "0" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------Do not allow users to log on using biometrics-------
:: ----------------------------------------------------------
echo --- Do not allow users to log on using biometrics
reg add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics\Credential Provider" /v "Enabled" /t "REG_DWORD" /d "0" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Disable Windows Biometric Service-------------
:: ----------------------------------------------------------
echo --- Disable Windows Biometric Service
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'WbioSrvc'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) {; Write-Host "^""Service `"^""$serviceName`"^"" could not be not found, no need to disable it."^""; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try {; Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else {; Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if(!$startupType) {; $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) {; $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if($startupType -eq 'Disabled') {; Write-Host "^""$serviceName is already disabled, no further action is needed"^""; }; <# -- 4. Disable service #>; try {; Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Disable Windows Insider Service--------------
:: ----------------------------------------------------------
echo --- Disable Windows Insider Service
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'wisvc'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) {; Write-Host "^""Service `"^""$serviceName`"^"" could not be not found, no need to disable it."^""; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try {; Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else {; Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if(!$startupType) {; $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) {; $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if($startupType -eq 'Disabled') {; Write-Host "^""$serviceName is already disabled, no further action is needed"^""; }; <# -- 4. Disable service #>; try {; Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----Do not let Microsoft try features on this build------
:: ----------------------------------------------------------
echo --- Do not let Microsoft try features on this build
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v "EnableExperimentation" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v "EnableConfigFlighting" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation" /v "value" /t "REG_DWORD" /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Disable getting preview builds of Windows---------
:: ----------------------------------------------------------
echo --- Disable getting preview builds of Windows
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v "AllowBuildPreview" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------Remove "Windows Insider Program" from Settings------
:: ----------------------------------------------------------
echo --- Remove "Windows Insider Program" from Settings
reg add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility" /v "HideInsiderPage" /t "REG_DWORD" /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Disable all settings sync-----------------
:: ----------------------------------------------------------
echo --- Disable all settings sync
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSyncUserOverride" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSyncOnPaidNetwork" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" /v "SyncPolicy" /t REG_DWORD /d 5 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Disable Application Setting Sync-------------
:: ----------------------------------------------------------
echo --- Disable Application Setting Sync
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableApplicationSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableApplicationSettingSyncUserOverride" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable App Sync Setting Sync---------------
:: ----------------------------------------------------------
echo --- Disable App Sync Setting Sync
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableAppSyncSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableAppSyncSettingSyncUserOverride" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Disable Credentials Setting Sync-------------
:: ----------------------------------------------------------
echo --- Disable Credentials Setting Sync
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableCredentialsSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableCredentialsSettingSyncUserOverride" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Disable Desktop Theme Setting Sync------------
:: ----------------------------------------------------------
echo --- Disable Desktop Theme Setting Sync
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableDesktopThemeSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableDesktopThemeSettingSyncUserOverride" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Disable Personalization Setting Sync-----------
:: ----------------------------------------------------------
echo --- Disable Personalization Setting Sync
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisablePersonalizationSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisablePersonalizationSettingSyncUserOverride" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Disable Start Layout Setting Sync-------------
:: ----------------------------------------------------------
echo --- Disable Start Layout Setting Sync
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableStartLayoutSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableStartLayoutSettingSyncUserOverride" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Disable Web Browser Setting Sync-------------
:: ----------------------------------------------------------
echo --- Disable Web Browser Setting Sync
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWebBrowserSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWebBrowserSettingSyncUserOverride" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Disable Windows Setting Sync---------------
:: ----------------------------------------------------------
echo --- Disable Windows Setting Sync
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWindowsSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWindowsSettingSyncUserOverride" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable Language Setting Sync---------------
:: ----------------------------------------------------------
echo --- Disable Language Setting Sync
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /t REG_DWORD /v "Enabled" /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Disable cloud speech recognition-------------
:: ----------------------------------------------------------
echo --- Disable cloud speech recognition
reg add "HKCU\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /t "REG_DWORD" /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----Disable active probing (pings to MSFT NCSI server)----
:: ----------------------------------------------------------
echo --- Disable active probing (pings to MSFT NCSI server)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet" /v "EnableActiveProbing" /t REG_DWORD /d "0" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Opt out from Windows privacy consent-----------
:: ----------------------------------------------------------
echo --- Opt out from Windows privacy consent
reg add "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------Disable Windows feedback-----------------
:: ----------------------------------------------------------
echo --- Disable Windows feedback
reg add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f 
reg delete "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d 1 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Disable text and handwriting collection----------
:: ----------------------------------------------------------
echo --- Disable text and handwriting collection
reg add "HKCU\Software\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "AllowInputPersonalization" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------------Turn off sensors---------------------
:: ----------------------------------------------------------
echo --- Turn off sensors
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableSensors" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Disable Website Access of Language List----------
:: ----------------------------------------------------------
echo --- Disable Website Access of Language List
reg add "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable Auto Downloading Maps---------------
:: ----------------------------------------------------------
echo --- Disable Auto Downloading Maps
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Maps" /v "AllowUntriggeredNetworkTrafficOnSettingsPage" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Maps" /v "AutoDownloadAndUpdateMapData" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------------Disable steps recorder------------------
:: ----------------------------------------------------------
echo --- Disable steps recorder
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable game screen recording---------------
:: ----------------------------------------------------------
echo --- Disable game screen recording
reg add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Disable Windows DRM internet access------------
:: ----------------------------------------------------------
echo --- Disable Windows DRM internet access
reg add "HKLM\SOFTWARE\Policies\Microsoft\WMDRM" /v "DisableOnline" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----Disable feedback on write (sending typing info)------
:: ----------------------------------------------------------
echo --- Disable feedback on write (sending typing info)
reg add "HKLM\SOFTWARE\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------------Disable Activity Feed-------------------
:: ----------------------------------------------------------
echo --- Disable Activity Feed
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /d "0" /t REG_DWORD /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Disable visual studio telemetry--------------
:: ----------------------------------------------------------
echo --- Disable visual studio telemetry
reg add "HKCU\Software\Microsoft\VisualStudio\Telemetry" /v "TurnOffSwitch" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable Visual Studio feedback--------------
:: ----------------------------------------------------------
echo --- Disable Visual Studio feedback
reg add "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" /v "DisableFeedbackDialog" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" /v "DisableEmailInput" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" /v "DisableScreenshotCapture" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: Stop and disable Visual Studio Standard Collector Service-
:: ----------------------------------------------------------
echo --- Stop and disable Visual Studio Standard Collector Service
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'VSStandardCollectorService150'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) {; Write-Host "^""Service `"^""$serviceName`"^"" could not be not found, no need to disable it."^""; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try {; Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else {; Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if(!$startupType) {; $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) {; $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if($startupType -eq 'Disabled') {; Write-Host "^""$serviceName is already disabled, no further action is needed"^""; }; <# -- 4. Disable service #>; try {; Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------------Disable SQM OS key--------------------
:: ----------------------------------------------------------
echo --- Disable SQM OS key
if %PROCESSOR_ARCHITECTURE%==x86 ( REM is 32 bit?
    reg add "HKLM\SOFTWARE\Microsoft\VSCommon\14.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Microsoft\VSCommon\15.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Microsoft\VSCommon\16.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f
) else (
    reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\14.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\15.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\16.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f
)
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------Disable SQM group policy-----------------
:: ----------------------------------------------------------
echo --- Disable SQM group policy
reg add "HKLM\Software\Policies\Microsoft\VisualStudio\SQM" /v "OptIn" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Uninstall NVIDIA telemetry tasks-------------
:: ----------------------------------------------------------
echo --- Uninstall NVIDIA telemetry tasks
if exist "%ProgramFiles%\NVIDIA Corporation\Installer2\InstallerCore\NVI2.DLL" (
    rundll32 "%PROGRAMFILES%\NVIDIA Corporation\Installer2\InstallerCore\NVI2.DLL",UninstallPackage NvTelemetryContainer
    rundll32 "%PROGRAMFILES%\NVIDIA Corporation\Installer2\InstallerCore\NVI2.DLL",UninstallPackage NvTelemetry
)
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Delete NVIDIA residual telemetry files----------
:: ----------------------------------------------------------
echo --- Delete NVIDIA residual telemetry files
del /s %SystemRoot%\System32\DriverStore\FileRepository\NvTelemetry*.dll
rmdir /s /q "%ProgramFiles(x86)%\NVIDIA Corporation\NvTelemetry" 2>nul
rmdir /s /q "%ProgramFiles%\NVIDIA Corporation\NvTelemetry" 2>nul
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Opt out from NVIDIA telemetry---------------
:: ----------------------------------------------------------
echo --- Opt out from NVIDIA telemetry
reg add "HKLM\SOFTWARE\NVIDIA Corporation\NvControlPanel2\Client" /v "OptInOrOutPreference" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID44231" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID64640" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID66610" /t REG_DWORD /d 0 /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\Startup" /v "SendTelemetryData" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Disable Nvidia Telemetry Container service--------
:: ----------------------------------------------------------
echo --- Disable Nvidia Telemetry Container service
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'NvTelemetryContainer'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) {; Write-Host "^""Service `"^""$serviceName`"^"" could not be not found, no need to disable it."^""; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try {; Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else {; Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if(!$startupType) {; $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) {; $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if($startupType -eq 'Disabled') {; Write-Host "^""$serviceName is already disabled, no further action is needed"^""; }; <# -- 4. Disable service #>; try {; Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Disable NVIDIA telemetry services-------------
:: ----------------------------------------------------------
echo --- Disable NVIDIA telemetry services
schtasks /change /TN NvTmMon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8} /DISABLE
schtasks /change /TN NvTmRep_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8} /DISABLE
schtasks /change /TN NvTmRepOnLogon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8} /DISABLE
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Disable Visual Studio Code telemetry-----------
:: ----------------------------------------------------------
echo --- Disable Visual Studio Code telemetry
PowerShell -ExecutionPolicy Unrestricted -Command "$jsonfile = "^""$env:APPDATA\Code\User\settings.json"^""; if (!(Test-Path $jsonfile -PathType Leaf)) {; Write-Host "^""No updates. Settings file was not at $jsonfile"^""; exit 0; }; $json = Get-Content $jsonfile | Out-String | ConvertFrom-Json; $json | Add-Member -Type NoteProperty -Name 'telemetry.enableTelemetry' -Value $false -Force; $json | ConvertTo-Json | Set-Content $jsonfile"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Disable Visual Studio Code crash reporting--------
:: ----------------------------------------------------------
echo --- Disable Visual Studio Code crash reporting
PowerShell -ExecutionPolicy Unrestricted -Command "$jsonfile = "^""$env:APPDATA\Code\User\settings.json"^""; if (!(Test-Path $jsonfile -PathType Leaf)) {; Write-Host "^""No updates. Settings file was not at $jsonfile"^""; exit 0; }; $json = Get-Content $jsonfile | Out-String | ConvertFrom-Json; $json | Add-Member -Type NoteProperty -Name 'telemetry.enableCrashReporter' -Value $false -Force; $json | ConvertTo-Json | Set-Content $jsonfile"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Do not run Microsoft online experiments----------
:: ----------------------------------------------------------
echo --- Do not run Microsoft online experiments
PowerShell -ExecutionPolicy Unrestricted -Command "$jsonfile = "^""$env:APPDATA\Code\User\settings.json"^""; if (!(Test-Path $jsonfile -PathType Leaf)) {; Write-Host "^""No updates. Settings file was not at $jsonfile"^""; exit 0; }; $json = Get-Content $jsonfile | Out-String | ConvertFrom-Json; $json | Add-Member -Type NoteProperty -Name 'workbench.enableExperiments' -Value $false -Force; $json | ConvertTo-Json | Set-Content $jsonfile"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Choose manual updates over automatic updates-------
:: ----------------------------------------------------------
echo --- Choose manual updates over automatic updates
PowerShell -ExecutionPolicy Unrestricted -Command "$jsonfile = "^""$env:APPDATA\Code\User\settings.json"^""; if (!(Test-Path $jsonfile -PathType Leaf)) {; Write-Host "^""No updates. Settings file was not at $jsonfile"^""; exit 0; }; $json = Get-Content $jsonfile | Out-String | ConvertFrom-Json; $json | Add-Member -Type NoteProperty -Name 'update.mode' -Value 'manual' -Force; $json | ConvertTo-Json | Set-Content $jsonfile"
:: ----------------------------------------------------------


:: Show Release Notes from Microsoft online service after an update
echo --- Show Release Notes from Microsoft online service after an update
PowerShell -ExecutionPolicy Unrestricted -Command "$jsonfile = "^""$env:APPDATA\Code\User\settings.json"^""; if (!(Test-Path $jsonfile -PathType Leaf)) {; Write-Host "^""No updates. Settings file was not at $jsonfile"^""; exit 0; }; $json = Get-Content $jsonfile | Out-String | ConvertFrom-Json; $json | Add-Member -Type NoteProperty -Name 'update.showReleaseNotes' -Value $false -Force; $json | ConvertTo-Json | Set-Content $jsonfile"
:: ----------------------------------------------------------


:: Automatically check extensions from Microsoft online service
echo --- Automatically check extensions from Microsoft online service
PowerShell -ExecutionPolicy Unrestricted -Command "$jsonfile = "^""$env:APPDATA\Code\User\settings.json"^""; if (!(Test-Path $jsonfile -PathType Leaf)) {; Write-Host "^""No updates. Settings file was not at $jsonfile"^""; exit 0; }; $json = Get-Content $jsonfile | Out-String | ConvertFrom-Json; $json | Add-Member -Type NoteProperty -Name 'extensions.autoCheckUpdates' -Value $false -Force; $json | ConvertTo-Json | Set-Content $jsonfile"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---Fetch recommendations from Microsoft only on demand----
:: ----------------------------------------------------------
echo --- Fetch recommendations from Microsoft only on demand
PowerShell -ExecutionPolicy Unrestricted -Command "$jsonfile = "^""$env:APPDATA\Code\User\settings.json"^""; if (!(Test-Path $jsonfile -PathType Leaf)) {; Write-Host "^""No updates. Settings file was not at $jsonfile"^""; exit 0; }; $json = Get-Content $jsonfile | Out-String | ConvertFrom-Json; $json | Add-Member -Type NoteProperty -Name 'extensions.showRecommendationsOnlyOnDemand' -Value $true -Force; $json | ConvertTo-Json | Set-Content $jsonfile"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --Automatically fetch git commits from remote repository--
:: ----------------------------------------------------------
echo --- Automatically fetch git commits from remote repository
PowerShell -ExecutionPolicy Unrestricted -Command "$jsonfile = "^""$env:APPDATA\Code\User\settings.json"^""; if (!(Test-Path $jsonfile -PathType Leaf)) {; Write-Host "^""No updates. Settings file was not at $jsonfile"^""; exit 0; }; $json = Get-Content $jsonfile | Out-String | ConvertFrom-Json; $json | Add-Member -Type NoteProperty -Name 'git.autofetch' -Value $false -Force; $json | ConvertTo-Json | Set-Content $jsonfile"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Fetch package information from NPM and Bower-------
:: ----------------------------------------------------------
echo --- Fetch package information from NPM and Bower
PowerShell -ExecutionPolicy Unrestricted -Command "$jsonfile = "^""$env:APPDATA\Code\User\settings.json"^""; if (!(Test-Path $jsonfile -PathType Leaf)) {; Write-Host "^""No updates. Settings file was not at $jsonfile"^""; exit 0; }; $json = Get-Content $jsonfile | Out-String | ConvertFrom-Json; $json | Add-Member -Type NoteProperty -Name 'npm.fetchOnlinePackageInfo' -Value $false -Force; $json | ConvertTo-Json | Set-Content $jsonfile"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Disable Microsoft Office logging-------------
:: ----------------------------------------------------------
echo --- Disable Microsoft Office logging
reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Outlook\Options\Mail" /v "EnableLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\Options\Mail" /v "EnableLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Outlook\Options\Calendar" /v "EnableCalendarLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\Options\Calendar" /v "EnableCalendarLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Word\Options" /v "EnableLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Word\Options" /v "EnableLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Office\15.0\OSM" /v "EnableLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\OSM" /v "EnableLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Office\15.0\OSM" /v "EnableUpload" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\OSM" /v "EnableUpload" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------Disable client telemetry-----------------
:: ----------------------------------------------------------
echo --- Disable client telemetry
reg add "HKCU\SOFTWARE\Microsoft\Office\Common\ClientTelemetry" /v "DisableTelemetry" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Common\ClientTelemetry" /v "DisableTelemetry" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\Common\ClientTelemetry" /v "VerboseLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Common\ClientTelemetry" /v "VerboseLogging" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Customer Experience Improvement Program----------
:: ----------------------------------------------------------
echo --- Customer Experience Improvement Program
reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Common" /v "QMEnable" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Common" /v "QMEnable" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------------Disable feedback---------------------
:: ----------------------------------------------------------
echo --- Disable feedback
reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Common\Feedback" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Common\Feedback" /v "Enabled" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------Disable telemetry agent------------------
:: ----------------------------------------------------------
echo --- Disable telemetry agent
schtasks /change /TN "Microsoft\Office\OfficeTelemetryAgentFallBack" /DISABLE
schtasks /change /TN "Microsoft\Office\OfficeTelemetryAgentFallBack2016" /DISABLE
schtasks /change /TN "Microsoft\Office\OfficeTelemetryAgentLogOn" /DISABLE
schtasks /change /TN "Microsoft\Office\OfficeTelemetryAgentLogOn2016" /DISABLE
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable Subscription Heartbeat--------------
:: ----------------------------------------------------------
echo --- Disable Subscription Heartbeat
schtasks /change /TN "Microsoft\Office\Office 15 Subscription Heartbeat" /DISABLE
schtasks /change /TN "Microsoft\Office\Office 16 Subscription Heartbeat" /DISABLE
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Do not send Windows Media Player statistics--------
:: ----------------------------------------------------------
echo --- Do not send Windows Media Player statistics
reg add "HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" /v "UsageTracking" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Disable metadata retrieval----------------
:: ----------------------------------------------------------
echo --- Disable metadata retrieval
reg add "HKCU\Software\Policies\Microsoft\WindowsMediaPlayer" /v "PreventCDDVDMetadataRetrieval" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\WindowsMediaPlayer" /v "PreventMusicFileMetadataRetrieval" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\WindowsMediaPlayer" /v "PreventRadioPresetsRetrieval" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\WMDRM" /v "DisableOnline" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---Disable Windows Media Player Network Sharing Service---
:: ----------------------------------------------------------
echo --- Disable Windows Media Player Network Sharing Service
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'WMPNetworkSvc'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) {; Write-Host "^""Service `"^""$serviceName`"^"" could not be not found, no need to disable it."^""; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try {; Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else {; Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if(!$startupType) {; $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) {; $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if($startupType -eq 'Disabled') {; Write-Host "^""$serviceName is already disabled, no further action is needed"^""; }; <# -- 4. Disable service #>; try {; Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable NET Core CLI telemetry--------------
:: ----------------------------------------------------------
echo --- Disable NET Core CLI telemetry
setx DOTNET_CLI_TELEMETRY_OPTOUT 1
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Disable PowerShell 7+ telemetry--------------
:: ----------------------------------------------------------
echo --- Disable PowerShell 7+ telemetry
setx POWERSHELL_TELEMETRY_OPTOUT 1
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable Google update service---------------
:: ----------------------------------------------------------
echo --- Disable Google update service
schtasks /change /disable /tn "GoogleUpdateTaskMachineCore"
schtasks /change /disable /tn "GoogleUpdateTaskMachineUA"
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'gupdate'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) {; Write-Host "^""Service `"^""$serviceName`"^"" could not be not found, no need to disable it."^""; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try {; Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else {; Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if(!$startupType) {; $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) {; $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if($startupType -eq 'Disabled') {; Write-Host "^""$serviceName is already disabled, no further action is needed"^""; }; <# -- 4. Disable service #>; try {; Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'gupdatem'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) {; Write-Host "^""Service `"^""$serviceName`"^"" could not be not found, no need to disable it."^""; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try {; Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else {; Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if(!$startupType) {; $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) {; $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if($startupType -eq 'Disabled') {; Write-Host "^""$serviceName is already disabled, no further action is needed"^""; }; <# -- 4. Disable service #>; try {; Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Disable Adobe Acrobat update service-----------
:: ----------------------------------------------------------
echo --- Disable Adobe Acrobat update service
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'AdobeARMservice'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) {; Write-Host "^""Service `"^""$serviceName`"^"" could not be not found, no need to disable it."^""; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try {; Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else {; Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if(!$startupType) {; $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) {; $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if($startupType -eq 'Disabled') {; Write-Host "^""$serviceName is already disabled, no further action is needed"^""; }; <# -- 4. Disable service #>; try {; Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'adobeupdateservice'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) {; Write-Host "^""Service `"^""$serviceName`"^"" could not be not found, no need to disable it."^""; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try {; Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else {; Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if(!$startupType) {; $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) {; $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if($startupType -eq 'Disabled') {; Write-Host "^""$serviceName is already disabled, no further action is needed"^""; }; <# -- 4. Disable service #>; try {; Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'adobeflashplayerupdatesvc'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) {; Write-Host "^""Service `"^""$serviceName`"^"" could not be not found, no need to disable it."^""; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try {; Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else {; Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if(!$startupType) {; $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) {; $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if($startupType -eq 'Disabled') {; Write-Host "^""$serviceName is already disabled, no further action is needed"^""; }; <# -- 4. Disable service #>; try {; Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
schtasks /change /tn "Adobe Acrobat Update Task" /disable
schtasks /change /tn "Adobe Flash Player Updater" /disable
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Disable Razer Game Scanner Service------------
:: ----------------------------------------------------------
echo --- Disable Razer Game Scanner Service
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'Razer Game Scanner Service'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) {; Write-Host "^""Service `"^""$serviceName`"^"" could not be not found, no need to disable it."^""; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try {; Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else {; Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if(!$startupType) {; $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) {; $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if($startupType -eq 'Disabled') {; Write-Host "^""$serviceName is already disabled, no further action is needed"^""; }; <# -- 4. Disable service #>; try {; Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Disable Logitech Gaming Registry Service---------
:: ----------------------------------------------------------
echo --- Disable Logitech Gaming Registry Service
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'LogiRegistryService'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) {; Write-Host "^""Service `"^""$serviceName`"^"" could not be not found, no need to disable it."^""; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try {; Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else {; Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if(!$startupType) {; $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) {; $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if($startupType -eq 'Disabled') {; Write-Host "^""$serviceName is already disabled, no further action is needed"^""; }; <# -- 4. Disable service #>; try {; Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Disable Dropbox auto update service------------
:: ----------------------------------------------------------
echo --- Disable Dropbox auto update service
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'dbupdate'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) {; Write-Host "^""Service `"^""$serviceName`"^"" could not be not found, no need to disable it."^""; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try {; Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else {; Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if(!$startupType) {; $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) {; $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if($startupType -eq 'Disabled') {; Write-Host "^""$serviceName is already disabled, no further action is needed"^""; }; <# -- 4. Disable service #>; try {; Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'dbupdatem'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) {; Write-Host "^""Service `"^""$serviceName`"^"" could not be not found, no need to disable it."^""; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try {; Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else {; Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if(!$startupType) {; $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) {; $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if($startupType -eq 'Disabled') {; Write-Host "^""$serviceName is already disabled, no further action is needed"^""; }; <# -- 4. Disable service #>; try {; Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
schtasks /Change /DISABLE /TN "DropboxUpdateTaskMachineCore"
schtasks /Change /DISABLE /TN "DropboxUpdateTaskMachineUA" 
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Disable CCleaner Monitoring----------------
:: ----------------------------------------------------------
echo --- Disable CCleaner Monitoring
reg add "HKCU\Software\Piriform\CCleaner" /v "Monitoring" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Piriform\CCleaner" /v "HelpImproveCCleaner" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Piriform\CCleaner" /v "SystemMonitoring" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Piriform\CCleaner" /v "UpdateAuto" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Piriform\CCleaner" /v "UpdateCheck" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Piriform\CCleaner" /v "CheckTrialOffer" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Piriform\CCleaner" /v "(Cfg)HealthCheck" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Piriform\CCleaner" /v "(Cfg)QuickClean" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Piriform\CCleaner" /v "(Cfg)QuickCleanIpm" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Piriform\CCleaner" /v "(Cfg)GetIpmForTrial" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Piriform\CCleaner" /v "(Cfg)SoftwareUpdater" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Piriform\CCleaner" /v "(Cfg)SoftwareUpdaterIpm" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Disable AutoPlay and AutoRun---------------
:: ----------------------------------------------------------
echo --- Disable AutoPlay and AutoRun
:: 255 (0xff) means all drives
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d 255 /f 
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutorun" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoAutoplayfornonVolume" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: Disable Windows Installer Always install with elevated privileges
echo --- Disable Windows Installer Always install with elevated privileges
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" /v "AlwaysInstallElevated" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Disable automatic updates-----------------
:: ----------------------------------------------------------
echo --- Disable automatic updates
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t "REG_DWORD" /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "AUOptions" /t "REG_DWORD" /d "2" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "ScheduledInstallDay" /t "REG_DWORD" /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "ScheduledInstallTime" /t "REG_DWORD" /d "3" /f
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'UsoSvc'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) {; Write-Host "^""Service `"^""$serviceName`"^"" could not be not found, no need to disable it."^""; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try {; Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else {; Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if(!$startupType) {; $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) {; $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if($startupType -eq 'Disabled') {; Write-Host "^""$serviceName is already disabled, no further action is needed"^""; }; <# -- 4. Disable service #>; try {; Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
:: ----------------------------------------------------------

:: Set maximum time possible for extended cloud check timeout
echo --- Set maximum time possible for extended cloud check timeout
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" /v "MpBafsExtendedTimeout" /t REG_DWORD /d 50 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Set lowest possible cloud protection level--------
:: ----------------------------------------------------------
echo --- Set lowest possible cloud protection level
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" /v "MpCloudBlockLevel" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: Disable receiving notifications to disable security intelligence
echo --- Disable receiving notifications to disable security intelligence
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "SignatureDisableNotification" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Turn off Windows Defender SpyNet reporting--------
:: ----------------------------------------------------------
echo --- Turn off Windows Defender SpyNet reporting
PowerShell -ExecutionPolicy Unrestricted -Command "$propertyName = 'MAPSReporting'; $value = '0'; if((Get-MpPreference -ErrorAction Ignore).$propertyName -eq $value) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is already `"^""$value`"^"" as desired."^""; exit 0; }; $command = Get-Command 'Set-MpPreference' -ErrorAction Ignore; if (!$command) {; Write-Warning 'Skipping. Command not found: "^""Set-MpPreference"^"".'; exit 0; }; if(!$command.Parameters.Keys.Contains($propertyName)) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; }; try {; Invoke-Expression "^""$($command.Name) -Force -$propertyName `$value -ErrorAction Stop"^""; Set-MpPreference -Force -MAPSReporting $value -ErrorAction Stop; Write-Host "^""Successfully set `"^""$propertyName`"^"" to `"^""$value`"^""."^""; exit 0; } catch {; if ( $_.FullyQualifiedErrorId -like '*0x800106ba*') {; Write-Warning "^""Cannot $($command.Name): Defender service (WinDefend) is not running. Try to enable it (revert) and re-run this?"^""; exit 0; } elseif (($_ | Out-String) -like '*Cannot convert*') {; Write-Host "^""Skipping. Argument `"^""$value`"^"" for property `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; } else {; Write-Error "^""Failed to set using $($command.Name): $_"^""; exit 1; }; }"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SpynetReporting" /t REG_DWORD /d "0" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------Do not send file samples for further analysis-------
:: ----------------------------------------------------------
echo --- Do not send file samples for further analysis
PowerShell -ExecutionPolicy Unrestricted -Command "$propertyName = 'SubmitSamplesConsent'; $value = '2'; if((Get-MpPreference -ErrorAction Ignore).$propertyName -eq $value) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is already `"^""$value`"^"" as desired."^""; exit 0; }; $command = Get-Command 'Set-MpPreference' -ErrorAction Ignore; if (!$command) {; Write-Warning 'Skipping. Command not found: "^""Set-MpPreference"^"".'; exit 0; }; if(!$command.Parameters.Keys.Contains($propertyName)) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; }; try {; Invoke-Expression "^""$($command.Name) -Force -$propertyName `$value -ErrorAction Stop"^""; Set-MpPreference -Force -SubmitSamplesConsent $value -ErrorAction Stop; Write-Host "^""Successfully set `"^""$propertyName`"^"" to `"^""$value`"^""."^""; exit 0; } catch {; if ( $_.FullyQualifiedErrorId -like '*0x800106ba*') {; Write-Warning "^""Cannot $($command.Name): Defender service (WinDefend) is not running. Try to enable it (revert) and re-run this?"^""; exit 0; } elseif (($_ | Out-String) -like '*Cannot convert*') {; Write-Host "^""Skipping. Argument `"^""$value`"^"" for property `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; } else {; Write-Error "^""Failed to set using $($command.Name): $_"^""; exit 1; }; }"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d "2" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: Disable Malicious Software Reporting tool diagnostic data-
:: ----------------------------------------------------------
echo --- Disable Malicious Software Reporting tool diagnostic data
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -Disable uploading files for threat analysis in real-time-
:: ----------------------------------------------------------
echo --- Disable uploading files for threat analysis in real-time
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "RealtimeSignatureDelivery" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: Disable prevention of users and apps from accessing dangerous websites
echo --- Disable prevention of users and apps from accessing dangerous websites
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" /v "EnableNetworkProtection" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Disable Controlled folder access-------------
:: ----------------------------------------------------------
echo --- Disable Controlled folder access
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access" /v "EnableControlledFolderAccess" /t REG_DWORD /d "0" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Disable protocol recognition---------------
:: ----------------------------------------------------------
echo --- Disable protocol recognition
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\NIS" /v "DisableProtocolRecognition" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable definition retirement---------------
:: ----------------------------------------------------------
echo --- Disable definition retirement
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\NIS\Consumers\IPS" /v "DisableSignatureRetirement" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Limit detection events rate to minimum----------
:: ----------------------------------------------------------
echo --- Limit detection events rate to minimum
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\NIS\Consumers\IPS" /v "ThrottleDetectionEventsRate" /t REG_DWORD /d "10000000" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Disable real-time monitoring---------------
:: ----------------------------------------------------------
echo --- Disable real-time monitoring
PowerShell -ExecutionPolicy Unrestricted -Command "$propertyName = 'DisableRealtimeMonitoring'; $value = $True; if((Get-MpPreference -ErrorAction Ignore).$propertyName -eq $value) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is already `"^""$value`"^"" as desired."^""; exit 0; }; $command = Get-Command 'Set-MpPreference' -ErrorAction Ignore; if (!$command) {; Write-Warning 'Skipping. Command not found: "^""Set-MpPreference"^"".'; exit 0; }; if(!$command.Parameters.Keys.Contains($propertyName)) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; }; try {; Invoke-Expression "^""$($command.Name) -Force -$propertyName `$value -ErrorAction Stop"^""; Set-MpPreference -Force -DisableRealtimeMonitoring $value -ErrorAction Stop; Write-Host "^""Successfully set `"^""$propertyName`"^"" to `"^""$value`"^""."^""; exit 0; } catch {; if ( $_.FullyQualifiedErrorId -like '*0x800106ba*') {; Write-Warning "^""Cannot $($command.Name): Defender service (WinDefend) is not running. Try to enable it (revert) and re-run this?"^""; exit 0; } elseif (($_ | Out-String) -like '*Cannot convert*') {; Write-Host "^""Skipping. Argument `"^""$value`"^"" for property `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; } else {; Write-Error "^""Failed to set using $($command.Name): $_"^""; exit 1; }; }"
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Disable Intrusion Prevention System (IPS)---------
:: ----------------------------------------------------------
echo --- Disable Intrusion Prevention System (IPS)
PowerShell -ExecutionPolicy Unrestricted -Command "$propertyName = 'DisableIntrusionPreventionSystem'; $value = $True; if((Get-MpPreference -ErrorAction Ignore).$propertyName -eq $value) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is already `"^""$value`"^"" as desired."^""; exit 0; }; $command = Get-Command 'Set-MpPreference' -ErrorAction Ignore; if (!$command) {; Write-Warning 'Skipping. Command not found: "^""Set-MpPreference"^"".'; exit 0; }; if(!$command.Parameters.Keys.Contains($propertyName)) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; }; try {; Invoke-Expression "^""$($command.Name) -Force -$propertyName `$value -ErrorAction Stop"^""; Set-MpPreference -Force -DisableIntrusionPreventionSystem $value -ErrorAction Stop; Write-Host "^""Successfully set `"^""$propertyName`"^"" to `"^""$value`"^""."^""; exit 0; } catch {; if ( $_.FullyQualifiedErrorId -like '*0x800106ba*') {; Write-Warning "^""Cannot $($command.Name): Defender service (WinDefend) is not running. Try to enable it (revert) and re-run this?"^""; exit 0; } elseif (($_ | Out-String) -like '*Cannot convert*') {; Write-Host "^""Skipping. Argument `"^""$value`"^"" for property `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; } else {; Write-Error "^""Failed to set using $($command.Name): $_"^""; exit 1; }; }"
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIntrusionPreventionSystem" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Disable Information Protection Control (IPC)-------
:: ----------------------------------------------------------
echo --- Disable Information Protection Control (IPC)
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableInformationProtectionControl" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----Disable process scanning on real-time protection-----
:: ----------------------------------------------------------
echo --- Disable process scanning on real-time protection
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Disable behavior monitoring----------------
:: ----------------------------------------------------------
echo --- Disable behavior monitoring
PowerShell -ExecutionPolicy Unrestricted -Command "$propertyName = 'DisableBehaviorMonitoring'; $value = $True; if((Get-MpPreference -ErrorAction Ignore).$propertyName -eq $value) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is already `"^""$value`"^"" as desired."^""; exit 0; }; $command = Get-Command 'Set-MpPreference' -ErrorAction Ignore; if (!$command) {; Write-Warning 'Skipping. Command not found: "^""Set-MpPreference"^"".'; exit 0; }; if(!$command.Parameters.Keys.Contains($propertyName)) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; }; try {; Invoke-Expression "^""$($command.Name) -Force -$propertyName `$value -ErrorAction Stop"^""; Set-MpPreference -Force -DisableBehaviorMonitoring $value -ErrorAction Stop; Write-Host "^""Successfully set `"^""$propertyName`"^"" to `"^""$value`"^""."^""; exit 0; } catch {; if ( $_.FullyQualifiedErrorId -like '*0x800106ba*') {; Write-Warning "^""Cannot $($command.Name): Defender service (WinDefend) is not running. Try to enable it (revert) and re-run this?"^""; exit 0; } elseif (($_ | Out-String) -like '*Cannot convert*') {; Write-Host "^""Skipping. Argument `"^""$value`"^"" for property `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; } else {; Write-Error "^""Failed to set using $($command.Name): $_"^""; exit 1; }; }"
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: Disable sending raw write notifications to behavior monitoring
echo --- Disable sending raw write notifications to behavior monitoring
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRawWriteNotification" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: Disable scanning for all downloaded files and attachments-
:: ----------------------------------------------------------
echo --- Disable scanning for all downloaded files and attachments
PowerShell -ExecutionPolicy Unrestricted -Command "$propertyName = 'DisableIOAVProtection'; $value = $True; if((Get-MpPreference -ErrorAction Ignore).$propertyName -eq $value) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is already `"^""$value`"^"" as desired."^""; exit 0; }; $command = Get-Command 'Set-MpPreference' -ErrorAction Ignore; if (!$command) {; Write-Warning 'Skipping. Command not found: "^""Set-MpPreference"^"".'; exit 0; }; if(!$command.Parameters.Keys.Contains($propertyName)) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; }; try {; Invoke-Expression "^""$($command.Name) -Force -$propertyName `$value -ErrorAction Stop"^""; Set-MpPreference -Force -DisableIOAVProtection $value -ErrorAction Stop; Write-Host "^""Successfully set `"^""$propertyName`"^"" to `"^""$value`"^""."^""; exit 0; } catch {; if ( $_.FullyQualifiedErrorId -like '*0x800106ba*') {; Write-Warning "^""Cannot $($command.Name): Defender service (WinDefend) is not running. Try to enable it (revert) and re-run this?"^""; exit 0; } elseif (($_ | Out-String) -like '*Cannot convert*') {; Write-Host "^""Skipping. Argument `"^""$value`"^"" for property `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; } else {; Write-Error "^""Failed to set using $($command.Name): $_"^""; exit 1; }; }"
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: Disable scanning files bigger than 1 KB (minimum possible)
echo --- Disable scanning files bigger than 1 KB (minimum possible)
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "IOAVMaxSize" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Disable monitoring file and program activity-------
:: ----------------------------------------------------------
echo --- Disable monitoring file and program activity
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: Disable bidirectional scanning of incoming and outgoing file and program activity
echo --- Disable bidirectional scanning of incoming and outgoing file and program activity
PowerShell -ExecutionPolicy Unrestricted -Command "$propertyName = 'RealTimeScanDirection'; $value = '1'; if((Get-MpPreference -ErrorAction Ignore).$propertyName -eq $value) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is already `"^""$value`"^"" as desired."^""; exit 0; }; $command = Get-Command 'Set-MpPreference' -ErrorAction Ignore; if (!$command) {; Write-Warning 'Skipping. Command not found: "^""Set-MpPreference"^"".'; exit 0; }; if(!$command.Parameters.Keys.Contains($propertyName)) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; }; try {; Invoke-Expression "^""$($command.Name) -Force -$propertyName `$value -ErrorAction Stop"^""; Set-MpPreference -Force -RealTimeScanDirection $value -ErrorAction Stop; Write-Host "^""Successfully set `"^""$propertyName`"^"" to `"^""$value`"^""."^""; exit 0; } catch {; if ( $_.FullyQualifiedErrorId -like '*0x800106ba*') {; Write-Warning "^""Cannot $($command.Name): Defender service (WinDefend) is not running. Try to enable it (revert) and re-run this?"^""; exit 0; } elseif (($_ | Out-String) -like '*Cannot convert*') {; Write-Host "^""Skipping. Argument `"^""$value`"^"" for property `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; } else {; Write-Error "^""Failed to set using $($command.Name): $_"^""; exit 1; }; }"
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "RealTimeScanDirection" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Disable routine remediation----------------
:: ----------------------------------------------------------
echo --- Disable routine remediation
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Disable running scheduled auto-remediation--------
:: ----------------------------------------------------------
echo --- Disable running scheduled auto-remediation
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Remediation" /v "Scan_ScheduleDay" /t REG_DWORD /d "8" /f
PowerShell -ExecutionPolicy Unrestricted -Command "$propertyName = 'RemediationScheduleDay'; $value = '8'; if((Get-MpPreference -ErrorAction Ignore).$propertyName -eq $value) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is already `"^""$value`"^"" as desired."^""; exit 0; }; $command = Get-Command 'Set-MpPreference' -ErrorAction Ignore; if (!$command) {; Write-Warning 'Skipping. Command not found: "^""Set-MpPreference"^"".'; exit 0; }; if(!$command.Parameters.Keys.Contains($propertyName)) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; }; try {; Invoke-Expression "^""$($command.Name) -Force -$propertyName `$value -ErrorAction Stop"^""; Set-MpPreference -Force -RemediationScheduleDay $value -ErrorAction Stop; Write-Host "^""Successfully set `"^""$propertyName`"^"" to `"^""$value`"^""."^""; exit 0; } catch {; if ( $_.FullyQualifiedErrorId -like '*0x800106ba*') {; Write-Warning "^""Cannot $($command.Name): Defender service (WinDefend) is not running. Try to enable it (revert) and re-run this?"^""; exit 0; } elseif (($_ | Out-String) -like '*Cannot convert*') {; Write-Host "^""Skipping. Argument `"^""$value`"^"" for property `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; } else {; Write-Error "^""Failed to set using $($command.Name): $_"^""; exit 1; }; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Disable remediation actions----------------
:: ----------------------------------------------------------
echo --- Disable remediation actions
PowerShell -ExecutionPolicy Unrestricted -Command "$propertyName = 'UnknownThreatDefaultAction'; $value = '9'; if((Get-MpPreference -ErrorAction Ignore).$propertyName -eq $value) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is already `"^""$value`"^"" as desired."^""; exit 0; }; $command = Get-Command 'Set-MpPreference' -ErrorAction Ignore; if (!$command) {; Write-Warning 'Skipping. Command not found: "^""Set-MpPreference"^"".'; exit 0; }; if(!$command.Parameters.Keys.Contains($propertyName)) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; }; try {; Invoke-Expression "^""$($command.Name) -Force -$propertyName `$value -ErrorAction Stop"^""; Set-MpPreference -Force -UnknownThreatDefaultAction $value -ErrorAction Stop; Write-Host "^""Successfully set `"^""$propertyName`"^"" to `"^""$value`"^""."^""; exit 0; } catch {; if ( $_.FullyQualifiedErrorId -like '*0x800106ba*') {; Write-Warning "^""Cannot $($command.Name): Defender service (WinDefend) is not running. Try to enable it (revert) and re-run this?"^""; exit 0; } elseif (($_ | Out-String) -like '*Cannot convert*') {; Write-Host "^""Skipping. Argument `"^""$value`"^"" for property `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; } else {; Write-Error "^""Failed to set using $($command.Name): $_"^""; exit 1; }; }"
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Threats" /v "Threats_ThreatSeverityDefaultAction" /t "REG_DWORD" /d "1" /f
:: 1: Clean, 2: Quarantine, 3: Remove, 6: Allow, 8: Ask user, 9: No action, 10: Block, NULL: default (based on the update definition)
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" /v "5" /t "REG_SZ" /d "9" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" /v "4" /t "REG_SZ" /d "9" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" /v "3" /t "REG_SZ" /d "9" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" /v "2" /t "REG_SZ" /d "9" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" /v "1" /t "REG_SZ" /d "9" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Auto-purge items from Quarantine folder----------
:: ----------------------------------------------------------
echo --- Auto-purge items from Quarantine folder
PowerShell -ExecutionPolicy Unrestricted -Command "$propertyName = 'QuarantinePurgeItemsAfterDelay'; $value = '1'; if((Get-MpPreference -ErrorAction Ignore).$propertyName -eq $value) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is already `"^""$value`"^"" as desired."^""; exit 0; }; $command = Get-Command 'Set-MpPreference' -ErrorAction Ignore; if (!$command) {; Write-Warning 'Skipping. Command not found: "^""Set-MpPreference"^"".'; exit 0; }; if(!$command.Parameters.Keys.Contains($propertyName)) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; }; try {; Invoke-Expression "^""$($command.Name) -Force -$propertyName `$value -ErrorAction Stop"^""; Set-MpPreference -Force -QuarantinePurgeItemsAfterDelay $value -ErrorAction Stop; Write-Host "^""Successfully set `"^""$propertyName`"^"" to `"^""$value`"^""."^""; exit 0; } catch {; if ( $_.FullyQualifiedErrorId -like '*0x800106ba*') {; Write-Warning "^""Cannot $($command.Name): Defender service (WinDefend) is not running. Try to enable it (revert) and re-run this?"^""; exit 0; } elseif (($_ | Out-String) -like '*Cannot convert*') {; Write-Host "^""Skipping. Argument `"^""$value`"^"" for property `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; } else {; Write-Error "^""Failed to set using $($command.Name): $_"^""; exit 1; }; }"
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Quarantine" /v "PurgeItemsAfterDelay" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Disable checking for signatures before scan--------
:: ----------------------------------------------------------
echo --- Disable checking for signatures before scan
PowerShell -ExecutionPolicy Unrestricted -Command "$propertyName = 'CheckForSignaturesBeforeRunningScan'; $value = $False; if((Get-MpPreference -ErrorAction Ignore).$propertyName -eq $value) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is already `"^""$value`"^"" as desired."^""; exit 0; }; $command = Get-Command 'Set-MpPreference' -ErrorAction Ignore; if (!$command) {; Write-Warning 'Skipping. Command not found: "^""Set-MpPreference"^"".'; exit 0; }; if(!$command.Parameters.Keys.Contains($propertyName)) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; }; try {; Invoke-Expression "^""$($command.Name) -Force -$propertyName `$value -ErrorAction Stop"^""; Set-MpPreference -Force -CheckForSignaturesBeforeRunningScan $value -ErrorAction Stop; Write-Host "^""Successfully set `"^""$propertyName`"^"" to `"^""$value`"^""."^""; exit 0; } catch {; if ( $_.FullyQualifiedErrorId -like '*0x800106ba*') {; Write-Warning "^""Cannot $($command.Name): Defender service (WinDefend) is not running. Try to enable it (revert) and re-run this?"^""; exit 0; } elseif (($_ | Out-String) -like '*Cannot convert*') {; Write-Host "^""Skipping. Argument `"^""$value`"^"" for property `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; } else {; Write-Error "^""Failed to set using $($command.Name): $_"^""; exit 1; }; }"
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "CheckForSignaturesBeforeRunningScan" /t REG_DWORD /d "0" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --Disable creating system restore point on a daily basis--
:: ----------------------------------------------------------
echo --- Disable creating system restore point on a daily basis
PowerShell -ExecutionPolicy Unrestricted -Command "$propertyName = 'DisableRestorePoint'; $value = $True; if((Get-MpPreference -ErrorAction Ignore).$propertyName -eq $value) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is already `"^""$value`"^"" as desired."^""; exit 0; }; $command = Get-Command 'Set-MpPreference' -ErrorAction Ignore; if (!$command) {; Write-Warning 'Skipping. Command not found: "^""Set-MpPreference"^"".'; exit 0; }; if(!$command.Parameters.Keys.Contains($propertyName)) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; }; try {; Invoke-Expression "^""$($command.Name) -Force -$propertyName `$value -ErrorAction Stop"^""; Set-MpPreference -Force -DisableRestorePoint $value -ErrorAction Stop; Write-Host "^""Successfully set `"^""$propertyName`"^"" to `"^""$value`"^""."^""; exit 0; } catch {; if ( $_.FullyQualifiedErrorId -like '*0x800106ba*') {; Write-Warning "^""Cannot $($command.Name): Defender service (WinDefend) is not running. Try to enable it (revert) and re-run this?"^""; exit 0; } elseif (($_ | Out-String) -like '*Cannot convert*') {; Write-Host "^""Skipping. Argument `"^""$value`"^"" for property `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; } else {; Write-Error "^""Failed to set using $($command.Name): $_"^""; exit 1; }; }"
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "DisableRestorePoint" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: Set minumum time for keeping files in scan history folder-
:: ----------------------------------------------------------
echo --- Set minumum time for keeping files in scan history folder
PowerShell -ExecutionPolicy Unrestricted -Command "$propertyName = 'ScanPurgeItemsAfterDelay'; $value = '1'; if((Get-MpPreference -ErrorAction Ignore).$propertyName -eq $value) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is already `"^""$value`"^"" as desired."^""; exit 0; }; $command = Get-Command 'Set-MpPreference' -ErrorAction Ignore; if (!$command) {; Write-Warning 'Skipping. Command not found: "^""Set-MpPreference"^"".'; exit 0; }; if(!$command.Parameters.Keys.Contains($propertyName)) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; }; try {; Invoke-Expression "^""$($command.Name) -Force -$propertyName `$value -ErrorAction Stop"^""; Set-MpPreference -Force -ScanPurgeItemsAfterDelay $value -ErrorAction Stop; Write-Host "^""Successfully set `"^""$propertyName`"^"" to `"^""$value`"^""."^""; exit 0; } catch {; if ( $_.FullyQualifiedErrorId -like '*0x800106ba*') {; Write-Warning "^""Cannot $($command.Name): Defender service (WinDefend) is not running. Try to enable it (revert) and re-run this?"^""; exit 0; } elseif (($_ | Out-String) -like '*Cannot convert*') {; Write-Host "^""Skipping. Argument `"^""$value`"^"" for property `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; } else {; Write-Error "^""Failed to set using $($command.Name): $_"^""; exit 1; }; }"
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "PurgeItemsAfterDelay" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----Set maximum days before a catch-up scan is forced-----
:: ----------------------------------------------------------
echo --- Set maximum days before a catch-up scan is forced
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "MissedScheduledScanCountBeforeCatchup" /t REG_DWORD /d "20" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Disable catch-up full scans----------------
:: ----------------------------------------------------------
echo --- Disable catch-up full scans
PowerShell -ExecutionPolicy Unrestricted -Command "$propertyName = 'DisableCatchupFullScan'; $value = $True; if((Get-MpPreference -ErrorAction Ignore).$propertyName -eq $value) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is already `"^""$value`"^"" as desired."^""; exit 0; }; $command = Get-Command 'Set-MpPreference' -ErrorAction Ignore; if (!$command) {; Write-Warning 'Skipping. Command not found: "^""Set-MpPreference"^"".'; exit 0; }; if(!$command.Parameters.Keys.Contains($propertyName)) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; }; try {; Invoke-Expression "^""$($command.Name) -Force -$propertyName `$value -ErrorAction Stop"^""; Set-MpPreference -Force -DisableCatchupFullScan $value -ErrorAction Stop; Write-Host "^""Successfully set `"^""$propertyName`"^"" to `"^""$value`"^""."^""; exit 0; } catch {; if ( $_.FullyQualifiedErrorId -like '*0x800106ba*') {; Write-Warning "^""Cannot $($command.Name): Defender service (WinDefend) is not running. Try to enable it (revert) and re-run this?"^""; exit 0; } elseif (($_ | Out-String) -like '*Cannot convert*') {; Write-Host "^""Skipping. Argument `"^""$value`"^"" for property `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; } else {; Write-Error "^""Failed to set using $($command.Name): $_"^""; exit 1; }; }"
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "DisableCatchupFullScan" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Disable catch-up quick scans---------------
:: ----------------------------------------------------------
echo --- Disable catch-up quick scans
PowerShell -ExecutionPolicy Unrestricted -Command "$propertyName = 'DisableCatchupQuickScan'; $value = $True; if((Get-MpPreference -ErrorAction Ignore).$propertyName -eq $value) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is already `"^""$value`"^"" as desired."^""; exit 0; }; $command = Get-Command 'Set-MpPreference' -ErrorAction Ignore; if (!$command) {; Write-Warning 'Skipping. Command not found: "^""Set-MpPreference"^"".'; exit 0; }; if(!$command.Parameters.Keys.Contains($propertyName)) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; }; try {; Invoke-Expression "^""$($command.Name) -Force -$propertyName `$value -ErrorAction Stop"^""; Set-MpPreference -Force -DisableCatchupQuickScan $value -ErrorAction Stop; Write-Host "^""Successfully set `"^""$propertyName`"^"" to `"^""$value`"^""."^""; exit 0; } catch {; if ( $_.FullyQualifiedErrorId -like '*0x800106ba*') {; Write-Warning "^""Cannot $($command.Name): Defender service (WinDefend) is not running. Try to enable it (revert) and re-run this?"^""; exit 0; } elseif (($_ | Out-String) -like '*Cannot convert*') {; Write-Host "^""Skipping. Argument `"^""$value`"^"" for property `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; } else {; Write-Error "^""Failed to set using $($command.Name): $_"^""; exit 1; }; }"
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "DisableCatchupQuickScan" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------Disable scan heuristics------------------
:: ----------------------------------------------------------
echo --- Disable scan heuristics
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "DisableHeuristics" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable scanning when not idle--------------
:: ----------------------------------------------------------
echo --- Disable scanning when not idle
PowerShell -ExecutionPolicy Unrestricted -Command "$propertyName = 'ScanOnlyIfIdleEnabled'; $value = $True; if((Get-MpPreference -ErrorAction Ignore).$propertyName -eq $value) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is already `"^""$value`"^"" as desired."^""; exit 0; }; $command = Get-Command 'Set-MpPreference' -ErrorAction Ignore; if (!$command) {; Write-Warning 'Skipping. Command not found: "^""Set-MpPreference"^"".'; exit 0; }; if(!$command.Parameters.Keys.Contains($propertyName)) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; }; try {; Invoke-Expression "^""$($command.Name) -Force -$propertyName `$value -ErrorAction Stop"^""; Set-MpPreference -Force -ScanOnlyIfIdleEnabled $value -ErrorAction Stop; Write-Host "^""Successfully set `"^""$propertyName`"^"" to `"^""$value`"^""."^""; exit 0; } catch {; if ( $_.FullyQualifiedErrorId -like '*0x800106ba*') {; Write-Warning "^""Cannot $($command.Name): Defender service (WinDefend) is not running. Try to enable it (revert) and re-run this?"^""; exit 0; } elseif (($_ | Out-String) -like '*Cannot convert*') {; Write-Host "^""Skipping. Argument `"^""$value`"^"" for property `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; } else {; Write-Error "^""Failed to set using $($command.Name): $_"^""; exit 1; }; }"
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "ScanOnlyIfIdle" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --Disable scheduled On Demand anti malware scanner (MRT)--
:: ----------------------------------------------------------
echo --- Disable scheduled On Demand anti malware scanner (MRT)
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Limit CPU usage during scans to minimum----------
:: ----------------------------------------------------------
echo --- Limit CPU usage during scans to minimum
PowerShell -ExecutionPolicy Unrestricted -Command "$propertyName = 'ScanAvgCPULoadFactor'; $value = '1'; if((Get-MpPreference -ErrorAction Ignore).$propertyName -eq $value) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is already `"^""$value`"^"" as desired."^""; exit 0; }; $command = Get-Command 'Set-MpPreference' -ErrorAction Ignore; if (!$command) {; Write-Warning 'Skipping. Command not found: "^""Set-MpPreference"^"".'; exit 0; }; if(!$command.Parameters.Keys.Contains($propertyName)) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; }; try {; Invoke-Expression "^""$($command.Name) -Force -$propertyName `$value -ErrorAction Stop"^""; Set-MpPreference -Force -ScanAvgCPULoadFactor $value -ErrorAction Stop; Write-Host "^""Successfully set `"^""$propertyName`"^"" to `"^""$value`"^""."^""; exit 0; } catch {; if ( $_.FullyQualifiedErrorId -like '*0x800106ba*') {; Write-Warning "^""Cannot $($command.Name): Defender service (WinDefend) is not running. Try to enable it (revert) and re-run this?"^""; exit 0; } elseif (($_ | Out-String) -like '*Cannot convert*') {; Write-Host "^""Skipping. Argument `"^""$value`"^"" for property `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; } else {; Write-Error "^""Failed to set using $($command.Name): $_"^""; exit 1; }; }"
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "AvgCPULoadFactor" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Limit CPU usage during idle scans to minumum-------
:: ----------------------------------------------------------
echo --- Limit CPU usage during idle scans to minumum
PowerShell -ExecutionPolicy Unrestricted -Command "$propertyName = 'DisableCpuThrottleOnIdleScans'; $value = $False; if((Get-MpPreference -ErrorAction Ignore).$propertyName -eq $value) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is already `"^""$value`"^"" as desired."^""; exit 0; }; $command = Get-Command 'Set-MpPreference' -ErrorAction Ignore; if (!$command) {; Write-Warning 'Skipping. Command not found: "^""Set-MpPreference"^"".'; exit 0; }; if(!$command.Parameters.Keys.Contains($propertyName)) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; }; try {; Invoke-Expression "^""$($command.Name) -Force -$propertyName `$value -ErrorAction Stop"^""; Set-MpPreference -Force -DisableCpuThrottleOnIdleScans $value -ErrorAction Stop; Write-Host "^""Successfully set `"^""$propertyName`"^"" to `"^""$value`"^""."^""; exit 0; } catch {; if ( $_.FullyQualifiedErrorId -like '*0x800106ba*') {; Write-Warning "^""Cannot $($command.Name): Defender service (WinDefend) is not running. Try to enable it (revert) and re-run this?"^""; exit 0; } elseif (($_ | Out-String) -like '*Cannot convert*') {; Write-Host "^""Skipping. Argument `"^""$value`"^"" for property `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; } else {; Write-Error "^""Failed to set using $($command.Name): $_"^""; exit 1; }; }"
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "DisableCpuThrottleOnIdleScans" /t REG_DWORD /d "0" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------Disable e-mail scanning------------------
:: ----------------------------------------------------------
echo --- Disable e-mail scanning
PowerShell -ExecutionPolicy Unrestricted -Command "$propertyName = 'DisableEmailScanning'; $value = $True; if((Get-MpPreference -ErrorAction Ignore).$propertyName -eq $value) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is already `"^""$value`"^"" as desired."^""; exit 0; }; $command = Get-Command 'Set-MpPreference' -ErrorAction Ignore; if (!$command) {; Write-Warning 'Skipping. Command not found: "^""Set-MpPreference"^"".'; exit 0; }; if(!$command.Parameters.Keys.Contains($propertyName)) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; }; try {; Invoke-Expression "^""$($command.Name) -Force -$propertyName `$value -ErrorAction Stop"^""; Set-MpPreference -Force -DisableEmailScanning $value -ErrorAction Stop; Write-Host "^""Successfully set `"^""$propertyName`"^"" to `"^""$value`"^""."^""; exit 0; } catch {; if ( $_.FullyQualifiedErrorId -like '*0x800106ba*') {; Write-Warning "^""Cannot $($command.Name): Defender service (WinDefend) is not running. Try to enable it (revert) and re-run this?"^""; exit 0; } elseif (($_ | Out-String) -like '*Cannot convert*') {; Write-Host "^""Skipping. Argument `"^""$value`"^"" for property `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; } else {; Write-Error "^""Failed to set using $($command.Name): $_"^""; exit 1; }; }"
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "DisableEmailScanning" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------Disable script scanning------------------
:: ----------------------------------------------------------
echo --- Disable script scanning
PowerShell -ExecutionPolicy Unrestricted -Command "$propertyName = 'DisableScriptScanning'; $value = $True; if((Get-MpPreference -ErrorAction Ignore).$propertyName -eq $value) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is already `"^""$value`"^"" as desired."^""; exit 0; }; $command = Get-Command 'Set-MpPreference' -ErrorAction Ignore; if (!$command) {; Write-Warning 'Skipping. Command not found: "^""Set-MpPreference"^"".'; exit 0; }; if(!$command.Parameters.Keys.Contains($propertyName)) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; }; try {; Invoke-Expression "^""$($command.Name) -Force -$propertyName `$value -ErrorAction Stop"^""; Set-MpPreference -Force -DisableScriptScanning $value -ErrorAction Stop; Write-Host "^""Successfully set `"^""$propertyName`"^"" to `"^""$value`"^""."^""; exit 0; } catch {; if ( $_.FullyQualifiedErrorId -like '*0x800106ba*') {; Write-Warning "^""Cannot $($command.Name): Defender service (WinDefend) is not running. Try to enable it (revert) and re-run this?"^""; exit 0; } elseif (($_ | Out-String) -like '*Cannot convert*') {; Write-Host "^""Skipping. Argument `"^""$value`"^"" for property `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; } else {; Write-Error "^""Failed to set using $($command.Name): $_"^""; exit 1; }; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable reparse point scanning--------------
:: ----------------------------------------------------------
echo --- Disable reparse point scanning
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "DisableReparsePointScanning" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --Disable scanning on mapped network drives on full-scan--
:: ----------------------------------------------------------
echo --- Disable scanning on mapped network drives on full-scan
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "DisableScanningMappedNetworkDrivesForFullScan" /t REG_DWORD /d "1" /f
PowerShell -ExecutionPolicy Unrestricted -Command "$propertyName = 'DisableScanningMappedNetworkDrivesForFullScan'; $value = $True; if((Get-MpPreference -ErrorAction Ignore).$propertyName -eq $value) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is already `"^""$value`"^"" as desired."^""; exit 0; }; $command = Get-Command 'Set-MpPreference' -ErrorAction Ignore; if (!$command) {; Write-Warning 'Skipping. Command not found: "^""Set-MpPreference"^"".'; exit 0; }; if(!$command.Parameters.Keys.Contains($propertyName)) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; }; try {; Invoke-Expression "^""$($command.Name) -Force -$propertyName `$value -ErrorAction Stop"^""; Set-MpPreference -Force -DisableScanningMappedNetworkDrivesForFullScan $value -ErrorAction Stop; Write-Host "^""Successfully set `"^""$propertyName`"^"" to `"^""$value`"^""."^""; exit 0; } catch {; if ( $_.FullyQualifiedErrorId -like '*0x800106ba*') {; Write-Warning "^""Cannot $($command.Name): Defender service (WinDefend) is not running. Try to enable it (revert) and re-run this?"^""; exit 0; } elseif (($_ | Out-String) -like '*Cannot convert*') {; Write-Host "^""Skipping. Argument `"^""$value`"^"" for property `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; } else {; Write-Error "^""Failed to set using $($command.Name): $_"^""; exit 1; }; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable scanning network files--------------
:: ----------------------------------------------------------
echo --- Disable scanning network files
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "DisableScanningNetworkFiles" /t REG_DWORD /d "1" /f
PowerShell -ExecutionPolicy Unrestricted -Command "$propertyName = 'DisableScanningNetworkFiles'; $value = $True; if((Get-MpPreference -ErrorAction Ignore).$propertyName -eq $value) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is already `"^""$value`"^"" as desired."^""; exit 0; }; $command = Get-Command 'Set-MpPreference' -ErrorAction Ignore; if (!$command) {; Write-Warning 'Skipping. Command not found: "^""Set-MpPreference"^"".'; exit 0; }; if(!$command.Parameters.Keys.Contains($propertyName)) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; }; try {; Invoke-Expression "^""$($command.Name) -Force -$propertyName `$value -ErrorAction Stop"^""; Set-MpPreference -Force -DisableScanningNetworkFiles $value -ErrorAction Stop; Write-Host "^""Successfully set `"^""$propertyName`"^"" to `"^""$value`"^""."^""; exit 0; } catch {; if ( $_.FullyQualifiedErrorId -like '*0x800106ba*') {; Write-Warning "^""Cannot $($command.Name): Defender service (WinDefend) is not running. Try to enable it (revert) and re-run this?"^""; exit 0; } elseif (($_ | Out-String) -like '*Cannot convert*') {; Write-Host "^""Skipping. Argument `"^""$value`"^"" for property `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; } else {; Write-Error "^""Failed to set using $($command.Name): $_"^""; exit 1; }; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Disable scanning packed executables------------
:: ----------------------------------------------------------
echo --- Disable scanning packed executables
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "DisablePackedExeScanning" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Disable scanning removable drives-------------
:: ----------------------------------------------------------
echo --- Disable scanning removable drives
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "DisableRemovableDriveScanning" /t REG_DWORD /d "1" /f
PowerShell -ExecutionPolicy Unrestricted -Command "$propertyName = 'DisableRemovableDriveScanning'; $value = $True; if((Get-MpPreference -ErrorAction Ignore).$propertyName -eq $value) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is already `"^""$value`"^"" as desired."^""; exit 0; }; $command = Get-Command 'Set-MpPreference' -ErrorAction Ignore; if (!$command) {; Write-Warning 'Skipping. Command not found: "^""Set-MpPreference"^"".'; exit 0; }; if(!$command.Parameters.Keys.Contains($propertyName)) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; }; try {; Invoke-Expression "^""$($command.Name) -Force -$propertyName `$value -ErrorAction Stop"^""; Set-MpPreference -Force -DisableRemovableDriveScanning $value -ErrorAction Stop; Write-Host "^""Successfully set `"^""$propertyName`"^"" to `"^""$value`"^""."^""; exit 0; } catch {; if ( $_.FullyQualifiedErrorId -like '*0x800106ba*') {; Write-Warning "^""Cannot $($command.Name): Defender service (WinDefend) is not running. Try to enable it (revert) and re-run this?"^""; exit 0; } elseif (($_ | Out-String) -like '*Cannot convert*') {; Write-Host "^""Skipping. Argument `"^""$value`"^"" for property `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; } else {; Write-Error "^""Failed to set using $($command.Name): $_"^""; exit 1; }; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable scanning archive files--------------
:: ----------------------------------------------------------
echo --- Disable scanning archive files
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "DisableArchiveScanning" /t REG_DWORD /d "1" /f
PowerShell -ExecutionPolicy Unrestricted -Command "$propertyName = 'DisableArchiveScanning'; $value = $True; if((Get-MpPreference -ErrorAction Ignore).$propertyName -eq $value) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is already `"^""$value`"^"" as desired."^""; exit 0; }; $command = Get-Command 'Set-MpPreference' -ErrorAction Ignore; if (!$command) {; Write-Warning 'Skipping. Command not found: "^""Set-MpPreference"^"".'; exit 0; }; if(!$command.Parameters.Keys.Contains($propertyName)) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; }; try {; Invoke-Expression "^""$($command.Name) -Force -$propertyName `$value -ErrorAction Stop"^""; Set-MpPreference -Force -DisableArchiveScanning $value -ErrorAction Stop; Write-Host "^""Successfully set `"^""$propertyName`"^"" to `"^""$value`"^""."^""; exit 0; } catch {; if ( $_.FullyQualifiedErrorId -like '*0x800106ba*') {; Write-Warning "^""Cannot $($command.Name): Defender service (WinDefend) is not running. Try to enable it (revert) and re-run this?"^""; exit 0; } elseif (($_ | Out-String) -like '*Cannot convert*') {; Write-Host "^""Skipping. Argument `"^""$value`"^"" for property `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; } else {; Write-Error "^""Failed to set using $($command.Name): $_"^""; exit 1; }; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----Limit depth for scanning archive files to minimum-----
:: ----------------------------------------------------------
echo --- Limit depth for scanning archive files to minimum
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "ArchiveMaxDepth" /t REG_DWORD /d "0" /f
:: ----------------------------------------------------------


:: Limit file size for archive files to be scanned to minimum
echo --- Limit file size for archive files to be scanned to minimum
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "ArchiveMaxSize" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------Disable scheduled scans------------------
:: ----------------------------------------------------------
echo --- Disable scheduled scans
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "ScheduleDay" /t REG_DWORD /d "8" /f
PowerShell -ExecutionPolicy Unrestricted -Command "$propertyName = 'ScanScheduleDay'; $value = '8'; if((Get-MpPreference -ErrorAction Ignore).$propertyName -eq $value) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is already `"^""$value`"^"" as desired."^""; exit 0; }; $command = Get-Command 'Set-MpPreference' -ErrorAction Ignore; if (!$command) {; Write-Warning 'Skipping. Command not found: "^""Set-MpPreference"^"".'; exit 0; }; if(!$command.Parameters.Keys.Contains($propertyName)) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; }; try {; Invoke-Expression "^""$($command.Name) -Force -$propertyName `$value -ErrorAction Stop"^""; Set-MpPreference -Force -ScanScheduleDay $value -ErrorAction Stop; Write-Host "^""Successfully set `"^""$propertyName`"^"" to `"^""$value`"^""."^""; exit 0; } catch {; if ( $_.FullyQualifiedErrorId -like '*0x800106ba*') {; Write-Warning "^""Cannot $($command.Name): Defender service (WinDefend) is not running. Try to enable it (revert) and re-run this?"^""; exit 0; } elseif (($_ | Out-String) -like '*Cannot convert*') {; Write-Host "^""Skipping. Argument `"^""$value`"^"" for property `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; } else {; Write-Error "^""Failed to set using $($command.Name): $_"^""; exit 1; }; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Disable randomizing scheduled task times---------
:: ----------------------------------------------------------
echo --- Disable randomizing scheduled task times
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "RandomizeScheduleTaskTimes" /t REG_DWORD /d "0" /f
PowerShell -ExecutionPolicy Unrestricted -Command "$propertyName = 'RandomizeScheduleTaskTimes'; $value = $False; if((Get-MpPreference -ErrorAction Ignore).$propertyName -eq $value) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is already `"^""$value`"^"" as desired."^""; exit 0; }; $command = Get-Command 'Set-MpPreference' -ErrorAction Ignore; if (!$command) {; Write-Warning 'Skipping. Command not found: "^""Set-MpPreference"^"".'; exit 0; }; if(!$command.Parameters.Keys.Contains($propertyName)) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; }; try {; Invoke-Expression "^""$($command.Name) -Force -$propertyName `$value -ErrorAction Stop"^""; Set-MpPreference -Force -RandomizeScheduleTaskTimes $value -ErrorAction Stop; Write-Host "^""Successfully set `"^""$propertyName`"^"" to `"^""$value`"^""."^""; exit 0; } catch {; if ( $_.FullyQualifiedErrorId -like '*0x800106ba*') {; Write-Warning "^""Cannot $($command.Name): Defender service (WinDefend) is not running. Try to enable it (revert) and re-run this?"^""; exit 0; } elseif (($_ | Out-String) -like '*Cannot convert*') {; Write-Host "^""Skipping. Argument `"^""$value`"^"" for property `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; } else {; Write-Error "^""Failed to set using $($command.Name): $_"^""; exit 1; }; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Disable scheduled full-scans---------------
:: ----------------------------------------------------------
echo --- Disable scheduled full-scans
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "ScanParameters" /t REG_DWORD /d "1" /f
PowerShell -ExecutionPolicy Unrestricted -Command "$propertyName = 'ScanParameters'; $value = '1'; if((Get-MpPreference -ErrorAction Ignore).$propertyName -eq $value) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is already `"^""$value`"^"" as desired."^""; exit 0; }; $command = Get-Command 'Set-MpPreference' -ErrorAction Ignore; if (!$command) {; Write-Warning 'Skipping. Command not found: "^""Set-MpPreference"^"".'; exit 0; }; if(!$command.Parameters.Keys.Contains($propertyName)) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; }; try {; Invoke-Expression "^""$($command.Name) -Force -$propertyName `$value -ErrorAction Stop"^""; Set-MpPreference -Force -ScanParameters $value -ErrorAction Stop; Write-Host "^""Successfully set `"^""$propertyName`"^"" to `"^""$value`"^""."^""; exit 0; } catch {; if ( $_.FullyQualifiedErrorId -like '*0x800106ba*') {; Write-Warning "^""Cannot $($command.Name): Defender service (WinDefend) is not running. Try to enable it (revert) and re-run this?"^""; exit 0; } elseif (($_ | Out-String) -like '*Cannot convert*') {; Write-Host "^""Skipping. Argument `"^""$value`"^"" for property `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; } else {; Write-Error "^""Failed to set using $($command.Name): $_"^""; exit 1; }; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Limit how many times quick scans run per day-------
:: ----------------------------------------------------------
echo --- Limit how many times quick scans run per day
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "QuickScanInterval" /t REG_DWORD /d "24" /f
:: ----------------------------------------------------------


:: Disable scanning after security intelligence (signature) update
echo --- Disable scanning after security intelligence (signature) update
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "DisableScanOnUpdate" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: Limit Defender updates to those that complete gradual release cycle
echo --- Limit Defender updates to those that complete gradual release cycle
PowerShell -ExecutionPolicy Unrestricted -Command "$propertyName = 'DisableGradualRelease'; $value = $True; if((Get-MpPreference -ErrorAction Ignore).$propertyName -eq $value) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is already `"^""$value`"^"" as desired."^""; exit 0; }; $command = Get-Command 'Set-MpPreference' -ErrorAction Ignore; if (!$command) {; Write-Warning 'Skipping. Command not found: "^""Set-MpPreference"^"".'; exit 0; }; if(!$command.Parameters.Keys.Contains($propertyName)) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; }; try {; Invoke-Expression "^""$($command.Name) -Force -$propertyName `$value -ErrorAction Stop"^""; Set-MpPreference -Force -DisableGradualRelease $value -ErrorAction Stop; Write-Host "^""Successfully set `"^""$propertyName`"^"" to `"^""$value`"^""."^""; exit 0; } catch {; if ( $_.FullyQualifiedErrorId -like '*0x800106ba*') {; Write-Warning "^""Cannot $($command.Name): Defender service (WinDefend) is not running. Try to enable it (revert) and re-run this?"^""; exit 0; } elseif (($_ | Out-String) -like '*Cannot convert*') {; Write-Host "^""Skipping. Argument `"^""$value`"^"" for property `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; } else {; Write-Error "^""Failed to set using $($command.Name): $_"^""; exit 1; }; }"
:: ----------------------------------------------------------


:: Limit Defender engine updates to those that complete gradual release cycle
echo --- Limit Defender engine updates to those that complete gradual release cycle
PowerShell -ExecutionPolicy Unrestricted -Command "$propertyName = 'EngineUpdatesChannel'; $value = 'Broad'; if((Get-MpPreference -ErrorAction Ignore).$propertyName -eq $value) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is already `"^""$value`"^"" as desired."^""; exit 0; }; $command = Get-Command 'Set-MpPreference' -ErrorAction Ignore; if (!$command) {; Write-Warning 'Skipping. Command not found: "^""Set-MpPreference"^"".'; exit 0; }; if(!$command.Parameters.Keys.Contains($propertyName)) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; }; try {; Invoke-Expression "^""$($command.Name) -Force -$propertyName `$value -ErrorAction Stop"^""; Set-MpPreference -Force -EngineUpdatesChannel $value -ErrorAction Stop; Write-Host "^""Successfully set `"^""$propertyName`"^"" to `"^""$value`"^""."^""; exit 0; } catch {; if ( $_.FullyQualifiedErrorId -like '*0x800106ba*') {; Write-Warning "^""Cannot $($command.Name): Defender service (WinDefend) is not running. Try to enable it (revert) and re-run this?"^""; exit 0; } elseif (($_ | Out-String) -like '*Cannot convert*') {; Write-Host "^""Skipping. Argument `"^""$value`"^"" for property `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; } else {; Write-Error "^""Failed to set using $($command.Name): $_"^""; exit 1; }; }"
:: ----------------------------------------------------------


:: Limit Defender platform updates to those that complete gradual release cycle
echo --- Limit Defender platform updates to those that complete gradual release cycle
PowerShell -ExecutionPolicy Unrestricted -Command "$propertyName = 'PlatformUpdatesChannel'; $value = 'Broad'; if((Get-MpPreference -ErrorAction Ignore).$propertyName -eq $value) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is already `"^""$value`"^"" as desired."^""; exit 0; }; $command = Get-Command 'Set-MpPreference' -ErrorAction Ignore; if (!$command) {; Write-Warning 'Skipping. Command not found: "^""Set-MpPreference"^"".'; exit 0; }; if(!$command.Parameters.Keys.Contains($propertyName)) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; }; try {; Invoke-Expression "^""$($command.Name) -Force -$propertyName `$value -ErrorAction Stop"^""; Set-MpPreference -Force -PlatformUpdatesChannel $value -ErrorAction Stop; Write-Host "^""Successfully set `"^""$propertyName`"^"" to `"^""$value`"^""."^""; exit 0; } catch {; if ( $_.FullyQualifiedErrorId -like '*0x800106ba*') {; Write-Warning "^""Cannot $($command.Name): Defender service (WinDefend) is not running. Try to enable it (revert) and re-run this?"^""; exit 0; } elseif (($_ | Out-String) -like '*Cannot convert*') {; Write-Host "^""Skipping. Argument `"^""$value`"^"" for property `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; } else {; Write-Error "^""Failed to set using $($command.Name): $_"^""; exit 1; }; }"
:: ----------------------------------------------------------


:: Limit Defender definition updates to those that complete gradual release cycle
echo --- Limit Defender definition updates to those that complete gradual release cycle
PowerShell -ExecutionPolicy Unrestricted -Command "$propertyName = 'DefinitionUpdatesChannel'; $value = 'Broad'; if((Get-MpPreference -ErrorAction Ignore).$propertyName -eq $value) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is already `"^""$value`"^"" as desired."^""; exit 0; }; $command = Get-Command 'Set-MpPreference' -ErrorAction Ignore; if (!$command) {; Write-Warning 'Skipping. Command not found: "^""Set-MpPreference"^"".'; exit 0; }; if(!$command.Parameters.Keys.Contains($propertyName)) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; }; try {; Invoke-Expression "^""$($command.Name) -Force -$propertyName `$value -ErrorAction Stop"^""; Set-MpPreference -Force -DefinitionUpdatesChannel $value -ErrorAction Stop; Write-Host "^""Successfully set `"^""$propertyName`"^"" to `"^""$value`"^""."^""; exit 0; } catch {; if ( $_.FullyQualifiedErrorId -like '*0x800106ba*') {; Write-Warning "^""Cannot $($command.Name): Defender service (WinDefend) is not running. Try to enable it (revert) and re-run this?"^""; exit 0; } elseif (($_ | Out-String) -like '*Cannot convert*') {; Write-Host "^""Skipping. Argument `"^""$value`"^"" for property `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; } else {; Write-Error "^""Failed to set using $($command.Name): $_"^""; exit 1; }; }"
:: ----------------------------------------------------------


:: Disable forced security intelligence (signature) updates from Microsoft Update
echo --- Disable forced security intelligence (signature) updates from Microsoft Update
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "ForceUpdateFromMU" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: Disable security intelligence (signature) updates when running on battery power
echo --- Disable security intelligence (signature) updates when running on battery power
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "DisableScheduledSignatureUpdateOnBattery" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: Disable checking for the latest virus and spyware security intelligence (signature) on startup
echo --- Disable checking for the latest virus and spyware security intelligence (signature) on startup
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "UpdateOnStartUp" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: Disable catch-up security intelligence (signature) updates
echo --- Disable catch-up security intelligence (signature) updates
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "SignatureUpdateCatchupInterval" /t REG_DWORD /d "0" /f
PowerShell -ExecutionPolicy Unrestricted -Command "$propertyName = 'SignatureUpdateCatchupInterval'; $value = '0'; if((Get-MpPreference -ErrorAction Ignore).$propertyName -eq $value) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is already `"^""$value`"^"" as desired."^""; exit 0; }; $command = Get-Command 'Set-MpPreference' -ErrorAction Ignore; if (!$command) {; Write-Warning 'Skipping. Command not found: "^""Set-MpPreference"^"".'; exit 0; }; if(!$command.Parameters.Keys.Contains($propertyName)) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; }; try {; Invoke-Expression "^""$($command.Name) -Force -$propertyName `$value -ErrorAction Stop"^""; Set-MpPreference -Force -SignatureUpdateCatchupInterval $value -ErrorAction Stop; Write-Host "^""Successfully set `"^""$propertyName`"^"" to `"^""$value`"^""."^""; exit 0; } catch {; if ( $_.FullyQualifiedErrorId -like '*0x800106ba*') {; Write-Warning "^""Cannot $($command.Name): Defender service (WinDefend) is not running. Try to enable it (revert) and re-run this?"^""; exit 0; } elseif (($_ | Out-String) -like '*Cannot convert*') {; Write-Host "^""Skipping. Argument `"^""$value`"^"" for property `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; } else {; Write-Error "^""Failed to set using $($command.Name): $_"^""; exit 1; }; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -Limit spyware security intelligence (signature) updates--
:: ----------------------------------------------------------
echo --- Limit spyware security intelligence (signature) updates
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "ASSignatureDue" /t REG_DWORD /d 4294967295 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --Limit virus security intelligence (signature) updates---
:: ----------------------------------------------------------
echo --- Limit virus security intelligence (signature) updates
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "AVSignatureDue" /t REG_DWORD /d 4294967295 /f
:: ----------------------------------------------------------


:: Disable security intelligence (signature) update on startup
echo --- Disable security intelligence (signature) update on startup
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "DisableUpdateOnStartupWithoutEngine" /t REG_DWORD /d 1 /f
PowerShell -ExecutionPolicy Unrestricted -Command "$propertyName = 'SignatureDisableUpdateOnStartupWithoutEngine'; $value = $True; if((Get-MpPreference -ErrorAction Ignore).$propertyName -eq $value) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is already `"^""$value`"^"" as desired."^""; exit 0; }; $command = Get-Command 'Set-MpPreference' -ErrorAction Ignore; if (!$command) {; Write-Warning 'Skipping. Command not found: "^""Set-MpPreference"^"".'; exit 0; }; if(!$command.Parameters.Keys.Contains($propertyName)) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; }; try {; Invoke-Expression "^""$($command.Name) -Force -$propertyName `$value -ErrorAction Stop"^""; Set-MpPreference -Force -SignatureDisableUpdateOnStartupWithoutEngine $value -ErrorAction Stop; Write-Host "^""Successfully set `"^""$propertyName`"^"" to `"^""$value`"^""."^""; exit 0; } catch {; if ( $_.FullyQualifiedErrorId -like '*0x800106ba*') {; Write-Warning "^""Cannot $($command.Name): Defender service (WinDefend) is not running. Try to enable it (revert) and re-run this?"^""; exit 0; } elseif (($_ | Out-String) -like '*Cannot convert*') {; Write-Host "^""Skipping. Argument `"^""$value`"^"" for property `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; } else {; Write-Error "^""Failed to set using $($command.Name): $_"^""; exit 1; }; }"
:: ----------------------------------------------------------


:: Disable automatically checking security intelligence (signature) updates
echo --- Disable automatically checking security intelligence (signature) updates
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "ScheduleDay" /t REG_DWORD /d "8" /f
PowerShell -ExecutionPolicy Unrestricted -Command "$propertyName = 'SignatureScheduleDay'; $value = '8'; if((Get-MpPreference -ErrorAction Ignore).$propertyName -eq $value) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is already `"^""$value`"^"" as desired."^""; exit 0; }; $command = Get-Command 'Set-MpPreference' -ErrorAction Ignore; if (!$command) {; Write-Warning 'Skipping. Command not found: "^""Set-MpPreference"^"".'; exit 0; }; if(!$command.Parameters.Keys.Contains($propertyName)) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; }; try {; Invoke-Expression "^""$($command.Name) -Force -$propertyName `$value -ErrorAction Stop"^""; Set-MpPreference -Force -SignatureScheduleDay $value -ErrorAction Stop; Write-Host "^""Successfully set `"^""$propertyName`"^"" to `"^""$value`"^""."^""; exit 0; } catch {; if ( $_.FullyQualifiedErrorId -like '*0x800106ba*') {; Write-Warning "^""Cannot $($command.Name): Defender service (WinDefend) is not running. Try to enable it (revert) and re-run this?"^""; exit 0; } elseif (($_ | Out-String) -like '*Cannot convert*') {; Write-Host "^""Skipping. Argument `"^""$value`"^"" for property `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; } else {; Write-Error "^""Failed to set using $($command.Name): $_"^""; exit 1; }; }"
:: ----------------------------------------------------------


:: Limit update checks for security intelligence (signature) updates
echo --- Limit update checks for security intelligence (signature) updates
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "SignatureUpdateInterval" /t REG_DWORD /d 24 /f
PowerShell -ExecutionPolicy Unrestricted -Command "$propertyName = 'SignatureUpdateInterval'; $value = '24'; if((Get-MpPreference -ErrorAction Ignore).$propertyName -eq $value) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is already `"^""$value`"^"" as desired."^""; exit 0; }; $command = Get-Command 'Set-MpPreference' -ErrorAction Ignore; if (!$command) {; Write-Warning 'Skipping. Command not found: "^""Set-MpPreference"^"".'; exit 0; }; if(!$command.Parameters.Keys.Contains($propertyName)) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; }; try {; Invoke-Expression "^""$($command.Name) -Force -$propertyName `$value -ErrorAction Stop"^""; Set-MpPreference -Force -SignatureUpdateInterval $value -ErrorAction Stop; Write-Host "^""Successfully set `"^""$propertyName`"^"" to `"^""$value`"^""."^""; exit 0; } catch {; if ( $_.FullyQualifiedErrorId -like '*0x800106ba*') {; Write-Warning "^""Cannot $($command.Name): Defender service (WinDefend) is not running. Try to enable it (revert) and re-run this?"^""; exit 0; } elseif (($_ | Out-String) -like '*Cannot convert*') {; Write-Host "^""Skipping. Argument `"^""$value`"^"" for property `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; } else {; Write-Error "^""Failed to set using $($command.Name): $_"^""; exit 1; }; }"
:: ----------------------------------------------------------


:: Disable definition updates through both WSUS and the Microsoft Malware Protection Center
echo --- Disable definition updates through both WSUS and the Microsoft Malware Protection Center
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "CheckAlternateHttpLocation" /t REG_DWORD /d "0" /f
:: ----------------------------------------------------------


:: Disable definition updates through both WSUS and Windows Update
echo --- Disable definition updates through both WSUS and Windows Update
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "CheckAlternateDownloadLocation" /t REG_DWORD /d "0" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Disable Windows Defender logging-------------
:: ----------------------------------------------------------
echo --- Disable Windows Defender logging
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /v "Start" /t REG_DWORD /d "0" /f
:: ----------------------------------------------------------


:: Disable ETW Provider of Windows Defender (Windows Event Logs)
echo --- Disable ETW Provider of Windows Defender (Windows Event Logs)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Windows Defender/Operational" /v "Enabled" /t Reg_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Windows Defender/WHC" /v "Enabled" /t Reg_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Do not send Watson events-----------------
:: ----------------------------------------------------------
echo --- Do not send Watson events
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /v "DisableGenericRePorts" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: Send minimum Windows software trace preprocessor (WPP Software Tracing) levels
echo --- Send minimum Windows software trace preprocessor (WPP Software Tracing) levels
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Reporting" /v "WppTracingLevel" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: Disable auditing events in Microsoft Defender Application Guard
echo --- Disable auditing events in Microsoft Defender Application Guard
reg add "HKLM\SOFTWARE\Policies\Microsoft\AppHVSI" /v "AuditApplicationGuard" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Hide Windows Defender Security Center icon--------
:: ----------------------------------------------------------
echo --- Hide Windows Defender Security Center icon
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray" /v "HideSystray" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: Remove "Scan with Windows Defender" option from context menu
echo --- Remove "Scan with Windows Defender" option from context menu
reg delete "HKLM\SOFTWARE\Classes\CLSID\{09A47860-11B0-4DA5-AFA5-26D86198A780}\InprocServer32" /va /f 2>nul
reg delete "HKCR\CLSID\{09A47860-11B0-4DA5-AFA5-26D86198A780}" /v "InprocServer32" /f 2>nul
reg delete "HKCR\*\shellex\ContextMenuHandlers" /v "EPP" /f 2>nul
reg delete "HKCR\Directory\shellex\ContextMenuHandlers" /v "EPP" /f 2>nul
reg delete "HKCR\Drive\shellex\ContextMenuHandlers" /v "EPP" /f 2>nul
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---Remove Windows Defender Security Center from taskbar---
:: ----------------------------------------------------------
echo --- Remove Windows Defender Security Center from taskbar
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /f 2>nul
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------Enable headless UI mode------------------
:: ----------------------------------------------------------
echo --- Enable headless UI mode
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\UX Configuration" /v "UILockdown" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Restrict threat history to administrators---------
:: ----------------------------------------------------------
echo --- Restrict threat history to administrators
PowerShell -ExecutionPolicy Unrestricted -Command "$propertyName = 'DisablePrivacyMode'; $value = $True; if((Get-MpPreference -ErrorAction Ignore).$propertyName -eq $value) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is already `"^""$value`"^"" as desired."^""; exit 0; }; $command = Get-Command 'Set-MpPreference' -ErrorAction Ignore; if (!$command) {; Write-Warning 'Skipping. Command not found: "^""Set-MpPreference"^"".'; exit 0; }; if(!$command.Parameters.Keys.Contains($propertyName)) {; Write-Host "^""Skipping. `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; }; try {; Invoke-Expression "^""$($command.Name) -Force -$propertyName `$value -ErrorAction Stop"^""; Set-MpPreference -Force -DisablePrivacyMode $value -ErrorAction Stop; Write-Host "^""Successfully set `"^""$propertyName`"^"" to `"^""$value`"^""."^""; exit 0; } catch {; if ( $_.FullyQualifiedErrorId -like '*0x800106ba*') {; Write-Warning "^""Cannot $($command.Name): Defender service (WinDefend) is not running. Try to enable it (revert) and re-run this?"^""; exit 0; } elseif (($_ | Out-String) -like '*Cannot convert*') {; Write-Host "^""Skipping. Argument `"^""$value`"^"" for property `"^""$propertyName`"^"" is not supported for `"^""$($command.Name)`"^""."^""; exit 0; } else {; Write-Error "^""Failed to set using $($command.Name): $_"^""; exit 1; }; }"
PowerShell -ExecutionPolicy Unrestricted -Command "$command = 'reg add "^""HKLM\SOFTWARE\Microsoft\Windows Defender\UX Configuration"^"" /v "^""DisablePrivacyMode"^"" /t REG_DWORD /d "^""1"^"" /f'; $trustedInstallerSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'); $trustedInstallerName = $trustedInstallerSid.Translate([System.Security.Principal.NTAccount]); $streamOutFile = New-TemporaryFile; $batchFile = New-TemporaryFile; try {; $batchFile = Rename-Item $batchFile "^""$($batchFile.BaseName).bat"^"" -PassThru; "^""@echo off`r`n$command`r`nexit 0"^"" | Out-File $batchFile -Encoding ASCII; $taskName = 'privacy.sexy invoke'; schtasks.exe /delete /tn "^""$taskName"^"" /f 2>&1 | Out-Null <# Clean if something went wrong before, suppress any output #>; $taskAction = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument "^""cmd /c `"^""$batchFile`"^"" > $streamOutFile 2>&1"^""; $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries; Register-ScheduledTask -TaskName $taskName -Action $taskAction -Settings $settings -Force -ErrorAction Stop | Out-Null; try {; ($scheduleService = New-Object -ComObject Schedule.Service).Connect(); $scheduleService.GetFolder('\').GetTask($taskName).RunEx($null, 0, 0, $trustedInstallerName) | Out-Null; $timeOutLimit = (Get-Date).AddMinutes(5); Write-Host "^""Running as $trustedInstallerName"^""; while((Get-ScheduledTaskInfo $taskName).LastTaskResult -eq 267009) {; Start-Sleep -Milliseconds 200; if((Get-Date) -gt $timeOutLimit) {; Write-Warning "^""Skipping results, it took so long to execute script."^""; break;; }; }; if (($result = (Get-ScheduledTaskInfo $taskName).LastTaskResult) -ne 0) {; Write-Error "^""Failed to execute with exit code: $result."^""; }; } finally {; schtasks.exe /delete /tn "^""$taskName"^"" /f | Out-Null <# Outputs only errors #>; }; Get-Content $streamOutFile; } finally {; Remove-Item $streamOutFile, $batchFile; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Hide the "Virus and threat protection" area--------
:: ----------------------------------------------------------
echo --- Hide the "Virus and threat protection" area
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Virus and threat protection" /v "UILockdown" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Hide the "Ransomware data recovery" area---------
:: ----------------------------------------------------------
echo --- Hide the "Ransomware data recovery" area
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Virus and threat protection" /v "HideRansomwareRecovery" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Hide the "Family options" area--------------
:: ----------------------------------------------------------
echo --- Hide the "Family options" area
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Family options" /v "UILockdown" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------Hide the "Device performance and health" area-------
:: ----------------------------------------------------------
echo --- Hide the "Device performance and health" area
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Device performance and health" /v "UILockdown" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Hide the "Account protection" area------------
:: ----------------------------------------------------------
echo --- Hide the "Account protection" area
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Account protection" /v "UILockdown" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Hide the "App and browser protection" area--------
:: ----------------------------------------------------------
echo --- Hide the "App and browser protection" area
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection" /v "UILockdown" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----Hide the "Firewall and network protection" area------
:: ----------------------------------------------------------
echo --- Hide the "Firewall and network protection" area
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Firewall and network protection" /v "UILockdown" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Hide the Device security area---------------
:: ----------------------------------------------------------
echo --- Hide the Device security area
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Device security" /v "UILockdown" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Disable the Clear TPM button---------------
:: ----------------------------------------------------------
echo --- Disable the Clear TPM button
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Device security" /v "DisableClearTpmButton" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Disable the Secure boot area button------------
:: ----------------------------------------------------------
echo --- Disable the Secure boot area button
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Device security" /v "HideSecureBoot" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --Hide the Security processor (TPM) troubleshooter page---
:: ----------------------------------------------------------
echo --- Hide the Security processor (TPM) troubleshooter page
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Device security" /v "HideTPMTroubleshooting" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Hide the TPM Firmware Update recommendation--------
:: ----------------------------------------------------------
echo --- Hide the TPM Firmware Update recommendation
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Device security" /v "DisableTpmFirmwareUpdateWarning" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: Disable Windows Action Center security and maintenance notifications
echo --- Disable Windows Action Center security and maintenance notifications
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v "Enabled" /t REG_DWORD /d "0" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---Disable all Windows Defender Antivirus notifications---
:: ----------------------------------------------------------
echo --- Disable all Windows Defender Antivirus notifications
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows Defender\UX Configuration" /v "Notification_Suppress" /t REG_DWORD /d "1" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows Defender\UX Configuration" /v "Notification_Suppress" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Suppress reboot notifications---------------
:: ----------------------------------------------------------
echo --- Suppress reboot notifications
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\UX Configuration" /v "SuppressRebootNotification" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------------Hide all notifications------------------
:: ----------------------------------------------------------
echo --- Hide all notifications
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" /v "DisableNotifications" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender Security Center\Notifications" /v "DisableNotifications" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Hide non-critical notifications--------------
:: ----------------------------------------------------------
echo --- Hide non-critical notifications
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender Security Center\Notifications" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Disable Windows Defender ExploitGuard task--------
:: ----------------------------------------------------------
echo --- Disable Windows Defender ExploitGuard task
schtasks /Change /TN "Microsoft\Windows\ExploitGuard\ExploitGuard MDM policy Refresh" /Disable 2>nul
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----Disable Windows Defender Cache Maintenance task------
:: ----------------------------------------------------------
echo --- Disable Windows Defender Cache Maintenance task
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable 2>nul
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Disable Windows Defender Cleanup task-----------
:: ----------------------------------------------------------
echo --- Disable Windows Defender Cleanup task
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable 2>nul
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Disable Windows Defender Scheduled Scan task-------
:: ----------------------------------------------------------
echo --- Disable Windows Defender Scheduled Scan task
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable 2>nul
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Disable Windows Defender Verification task--------
:: ----------------------------------------------------------
echo --- Disable Windows Defender Verification task
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable 2>nul
:: ----------------------------------------------------------


:: Disable Windows Defender Firewall service (breaks Microsoft Store and `netsh advfirewall` CLI)
echo --- Disable Windows Defender Firewall service (breaks Microsoft Store and `netsh advfirewall` CLI)
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceQuery = 'MpsSvc'; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceQuery -ErrorAction SilentlyContinue; if(!$service) {; Write-Host "^""Service query `"^""$serviceQuery`"^"" did not yield any results, no need to disable it."^""; Exit 0; }; $serviceName = $service.Name; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host "^""`"^""$serviceName`"^"" is running, trying to stop it."^""; try {; Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else {; Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if service info is not found in registry #>; $registryKey = "^""HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"^""; if(!(Test-Path $registryKey)) {; Write-Host "^""`"^""$registryKey`"^"" is not found in registry, cannot enable it."^""; Exit 0; }; <# -- 4. Skip if already disabled #>; if( $(Get-ItemProperty -Path "^""$registryKey"^"").Start -eq 4) {; Write-Host "^""`"^""$serviceName`"^"" is already disabled from start, no further action is needed."^""; Exit 0; }; <# -- 5. Disable service #>; try {; Set-ItemProperty $registryKey -Name Start -Value 4 -Force -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
if exist "%WinDir%\system32\mpssvc.dll" (
    takeown /f "%WinDir%\system32\mpssvc.dll"
    icacls "%WinDir%\system32\mpssvc.dll" /grant administrators:F
    move "%WinDir%\system32\mpssvc.dll" "%WinDir%\system32\mpssvc.dll.OLD" && (
        echo Moved "%WinDir%\system32\mpssvc.dll" to "%WinDir%\system32\mpssvc.dll.OLD"
    ) || (
        echo Could not move %WinDir%\system32\mpssvc.dll 1>&2
    )
) else (
    echo No action required: %WinDir%\system32\mpssvc.dll is not found.
)
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Disable Windows Defender Antivirus service--------
:: ----------------------------------------------------------
echo --- Disable Windows Defender Antivirus service
PowerShell -ExecutionPolicy Unrestricted -Command "$command = 'sc stop "^""WinDefend"^"" >nul & sc config "^""WinDefend"^"" start=disabled'; $trustedInstallerSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'); $trustedInstallerName = $trustedInstallerSid.Translate([System.Security.Principal.NTAccount]); $streamOutFile = New-TemporaryFile; $batchFile = New-TemporaryFile; try {; $batchFile = Rename-Item $batchFile "^""$($batchFile.BaseName).bat"^"" -PassThru; "^""@echo off`r`n$command`r`nexit 0"^"" | Out-File $batchFile -Encoding ASCII; $taskName = 'privacy.sexy invoke'; schtasks.exe /delete /tn "^""$taskName"^"" /f 2>&1 | Out-Null <# Clean if something went wrong before, suppress any output #>; $taskAction = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument "^""cmd /c `"^""$batchFile`"^"" > $streamOutFile 2>&1"^""; $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries; Register-ScheduledTask -TaskName $taskName -Action $taskAction -Settings $settings -Force -ErrorAction Stop | Out-Null; try {; ($scheduleService = New-Object -ComObject Schedule.Service).Connect(); $scheduleService.GetFolder('\').GetTask($taskName).RunEx($null, 0, 0, $trustedInstallerName) | Out-Null; $timeOutLimit = (Get-Date).AddMinutes(5); Write-Host "^""Running as $trustedInstallerName"^""; while((Get-ScheduledTaskInfo $taskName).LastTaskResult -eq 267009) {; Start-Sleep -Milliseconds 200; if((Get-Date) -gt $timeOutLimit) {; Write-Warning "^""Skipping results, it took so long to execute script."^""; break;; }; }; if (($result = (Get-ScheduledTaskInfo $taskName).LastTaskResult) -ne 0) {; Write-Error "^""Failed to execute with exit code: $result."^""; }; } finally {; schtasks.exe /delete /tn "^""$taskName"^"" /f | Out-Null <# Outputs only errors #>; }; Get-Content $streamOutFile; } finally {; Remove-Item $streamOutFile, $batchFile; }"
:: ----------------------------------------------------------


:: Disable Microsoft Defender Antivirus Network Inspection service
echo --- Disable Microsoft Defender Antivirus Network Inspection service
PowerShell -ExecutionPolicy Unrestricted -Command "$command = 'sc stop "^""WdNisSvc"^"" >nul & sc config "^""WdNisSvc"^"" start=disabled'; $trustedInstallerSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'); $trustedInstallerName = $trustedInstallerSid.Translate([System.Security.Principal.NTAccount]); $streamOutFile = New-TemporaryFile; $batchFile = New-TemporaryFile; try {; $batchFile = Rename-Item $batchFile "^""$($batchFile.BaseName).bat"^"" -PassThru; "^""@echo off`r`n$command`r`nexit 0"^"" | Out-File $batchFile -Encoding ASCII; $taskName = 'privacy.sexy invoke'; schtasks.exe /delete /tn "^""$taskName"^"" /f 2>&1 | Out-Null <# Clean if something went wrong before, suppress any output #>; $taskAction = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument "^""cmd /c `"^""$batchFile`"^"" > $streamOutFile 2>&1"^""; $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries; Register-ScheduledTask -TaskName $taskName -Action $taskAction -Settings $settings -Force -ErrorAction Stop | Out-Null; try {; ($scheduleService = New-Object -ComObject Schedule.Service).Connect(); $scheduleService.GetFolder('\').GetTask($taskName).RunEx($null, 0, 0, $trustedInstallerName) | Out-Null; $timeOutLimit = (Get-Date).AddMinutes(5); Write-Host "^""Running as $trustedInstallerName"^""; while((Get-ScheduledTaskInfo $taskName).LastTaskResult -eq 267009) {; Start-Sleep -Milliseconds 200; if((Get-Date) -gt $timeOutLimit) {; Write-Warning "^""Skipping results, it took so long to execute script."^""; break;; }; }; if (($result = (Get-ScheduledTaskInfo $taskName).LastTaskResult) -ne 0) {; Write-Error "^""Failed to execute with exit code: $result."^""; }; } finally {; schtasks.exe /delete /tn "^""$taskName"^"" /f | Out-Null <# Outputs only errors #>; }; Get-Content $streamOutFile; } finally {; Remove-Item $streamOutFile, $batchFile; }"
:: ----------------------------------------------------------


:: Disable Windows Defender Advanced Threat Protection Service service
echo --- Disable Windows Defender Advanced Threat Protection Service service
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceQuery = 'Sense'; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceQuery -ErrorAction SilentlyContinue; if(!$service) {; Write-Host "^""Service query `"^""$serviceQuery`"^"" did not yield any results, no need to disable it."^""; Exit 0; }; $serviceName = $service.Name; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host "^""`"^""$serviceName`"^"" is running, trying to stop it."^""; try {; Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else {; Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if service info is not found in registry #>; $registryKey = "^""HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"^""; if(!(Test-Path $registryKey)) {; Write-Host "^""`"^""$registryKey`"^"" is not found in registry, cannot enable it."^""; Exit 0; }; <# -- 4. Skip if already disabled #>; if( $(Get-ItemProperty -Path "^""$registryKey"^"").Start -eq 4) {; Write-Host "^""`"^""$serviceName`"^"" is already disabled from start, no further action is needed."^""; Exit 0; }; <# -- 5. Disable service #>; try {; Set-ItemProperty $registryKey -Name Start -Value 4 -Force -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
if exist "%ProgramFiles%\Windows Defender Advanced Threat Protection\MsSense.exe" (
    takeown /f "%ProgramFiles%\Windows Defender Advanced Threat Protection\MsSense.exe"
    icacls "%ProgramFiles%\Windows Defender Advanced Threat Protection\MsSense.exe" /grant administrators:F
    move "%ProgramFiles%\Windows Defender Advanced Threat Protection\MsSense.exe" "%ProgramFiles%\Windows Defender Advanced Threat Protection\MsSense.exe.OLD" && (
        echo Moved "%ProgramFiles%\Windows Defender Advanced Threat Protection\MsSense.exe" to "%ProgramFiles%\Windows Defender Advanced Threat Protection\MsSense.exe.OLD"
    ) || (
        echo Could not move %ProgramFiles%\Windows Defender Advanced Threat Protection\MsSense.exe 1>&2
    )
) else (
    echo No action required: %ProgramFiles%\Windows Defender Advanced Threat Protection\MsSense.exe is not found.
)
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----Disable Windows Defender Security Center Service-----
:: ----------------------------------------------------------
echo --- Disable Windows Defender Security Center Service
PowerShell -ExecutionPolicy Unrestricted -Command "$command = 'reg add "^""HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService"^"" /v Start /t REG_DWORD /d 4 /f'; $trustedInstallerSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'); $trustedInstallerName = $trustedInstallerSid.Translate([System.Security.Principal.NTAccount]); $streamOutFile = New-TemporaryFile; $batchFile = New-TemporaryFile; try {; $batchFile = Rename-Item $batchFile "^""$($batchFile.BaseName).bat"^"" -PassThru; "^""@echo off`r`n$command`r`nexit 0"^"" | Out-File $batchFile -Encoding ASCII; $taskName = 'privacy.sexy invoke'; schtasks.exe /delete /tn "^""$taskName"^"" /f 2>&1 | Out-Null <# Clean if something went wrong before, suppress any output #>; $taskAction = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument "^""cmd /c `"^""$batchFile`"^"" > $streamOutFile 2>&1"^""; $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries; Register-ScheduledTask -TaskName $taskName -Action $taskAction -Settings $settings -Force -ErrorAction Stop | Out-Null; try {; ($scheduleService = New-Object -ComObject Schedule.Service).Connect(); $scheduleService.GetFolder('\').GetTask($taskName).RunEx($null, 0, 0, $trustedInstallerName) | Out-Null; $timeOutLimit = (Get-Date).AddMinutes(5); Write-Host "^""Running as $trustedInstallerName"^""; while((Get-ScheduledTaskInfo $taskName).LastTaskResult -eq 267009) {; Start-Sleep -Milliseconds 200; if((Get-Date) -gt $timeOutLimit) {; Write-Warning "^""Skipping results, it took so long to execute script."^""; break;; }; }; if (($result = (Get-ScheduledTaskInfo $taskName).LastTaskResult) -ne 0) {; Write-Error "^""Failed to execute with exit code: $result."^""; }; } finally {; schtasks.exe /delete /tn "^""$taskName"^"" /f | Out-Null <# Outputs only errors #>; }; Get-Content $streamOutFile; } finally {; Remove-Item $streamOutFile, $batchFile; }"
if exist "%WinDir%\system32\SecurityHealthService.exe" (
    takeown /f "%WinDir%\system32\SecurityHealthService.exe"
    icacls "%WinDir%\system32\SecurityHealthService.exe" /grant administrators:F
    move "%WinDir%\system32\SecurityHealthService.exe" "%WinDir%\system32\SecurityHealthService.exe.OLD" && (
        echo Moved "%WinDir%\system32\SecurityHealthService.exe" to "%WinDir%\system32\SecurityHealthService.exe.OLD"
    ) || (
        echo Could not move %WinDir%\system32\SecurityHealthService.exe 1>&2
    )
) else (
    echo No action required: %WinDir%\system32\SecurityHealthService.exe is not found.
)
:: ----------------------------------------------------------


:: Disable Windows Defender Firewall Authorization Driver service (breaks `netsh advfirewall` CLI)
echo --- Disable Windows Defender Firewall Authorization Driver service (breaks `netsh advfirewall` CLI)
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceQuery = 'mpsdrv'; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceQuery -ErrorAction SilentlyContinue; if(!$service) {; Write-Host "^""Service query `"^""$serviceQuery`"^"" did not yield any results, no need to disable it."^""; Exit 0; }; $serviceName = $service.Name; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host "^""`"^""$serviceName`"^"" is running, trying to stop it."^""; try {; Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else {; Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if service info is not found in registry #>; $registryKey = "^""HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"^""; if(!(Test-Path $registryKey)) {; Write-Host "^""`"^""$registryKey`"^"" is not found in registry, cannot enable it."^""; Exit 0; }; <# -- 4. Skip if already disabled #>; if( $(Get-ItemProperty -Path "^""$registryKey"^"").Start -eq 4) {; Write-Host "^""`"^""$serviceName`"^"" is already disabled from start, no further action is needed."^""; Exit 0; }; <# -- 5. Disable service #>; try {; Set-ItemProperty $registryKey -Name Start -Value 4 -Force -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
if exist "%SystemRoot%\System32\drivers\mpsdrv.sys" (
    takeown /f "%SystemRoot%\System32\drivers\mpsdrv.sys"
    icacls "%SystemRoot%\System32\drivers\mpsdrv.sys" /grant administrators:F
    move "%SystemRoot%\System32\drivers\mpsdrv.sys" "%SystemRoot%\System32\drivers\mpsdrv.sys.OLD" && (
        echo Moved "%SystemRoot%\System32\drivers\mpsdrv.sys" to "%SystemRoot%\System32\drivers\mpsdrv.sys.OLD"
    ) || (
        echo Could not move %SystemRoot%\System32\drivers\mpsdrv.sys 1>&2
    )
) else (
    echo No action required: %SystemRoot%\System32\drivers\mpsdrv.sys is not found.
)
:: ----------------------------------------------------------


:: Disable Microsoft Defender Antivirus Network Inspection System Driver service
echo --- Disable Microsoft Defender Antivirus Network Inspection System Driver service
PowerShell -ExecutionPolicy Unrestricted -Command "$command = 'net stop "^""WdNisDrv"^"" /yes >nul & sc config "^""WdNisDrv"^"" start=disabled'; $trustedInstallerSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'); $trustedInstallerName = $trustedInstallerSid.Translate([System.Security.Principal.NTAccount]); $streamOutFile = New-TemporaryFile; $batchFile = New-TemporaryFile; try {; $batchFile = Rename-Item $batchFile "^""$($batchFile.BaseName).bat"^"" -PassThru; "^""@echo off`r`n$command`r`nexit 0"^"" | Out-File $batchFile -Encoding ASCII; $taskName = 'privacy.sexy invoke'; schtasks.exe /delete /tn "^""$taskName"^"" /f 2>&1 | Out-Null <# Clean if something went wrong before, suppress any output #>; $taskAction = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument "^""cmd /c `"^""$batchFile`"^"" > $streamOutFile 2>&1"^""; $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries; Register-ScheduledTask -TaskName $taskName -Action $taskAction -Settings $settings -Force -ErrorAction Stop | Out-Null; try {; ($scheduleService = New-Object -ComObject Schedule.Service).Connect(); $scheduleService.GetFolder('\').GetTask($taskName).RunEx($null, 0, 0, $trustedInstallerName) | Out-Null; $timeOutLimit = (Get-Date).AddMinutes(5); Write-Host "^""Running as $trustedInstallerName"^""; while((Get-ScheduledTaskInfo $taskName).LastTaskResult -eq 267009) {; Start-Sleep -Milliseconds 200; if((Get-Date) -gt $timeOutLimit) {; Write-Warning "^""Skipping results, it took so long to execute script."^""; break;; }; }; if (($result = (Get-ScheduledTaskInfo $taskName).LastTaskResult) -ne 0) {; Write-Error "^""Failed to execute with exit code: $result."^""; }; } finally {; schtasks.exe /delete /tn "^""$taskName"^"" /f | Out-Null <# Outputs only errors #>; }; Get-Content $streamOutFile; } finally {; Remove-Item $streamOutFile, $batchFile; }"
if exist "%SystemRoot%\System32\drivers\WdNisDrv.sys" (
    takeown /f "%SystemRoot%\System32\drivers\WdNisDrv.sys"
    icacls "%SystemRoot%\System32\drivers\WdNisDrv.sys" /grant administrators:F
    move "%SystemRoot%\System32\drivers\WdNisDrv.sys" "%SystemRoot%\System32\drivers\WdNisDrv.sys.OLD" && (
        echo Moved "%SystemRoot%\System32\drivers\WdNisDrv.sys" to "%SystemRoot%\System32\drivers\WdNisDrv.sys.OLD"
    ) || (
        echo Could not move %SystemRoot%\System32\drivers\WdNisDrv.sys 1>&2
    )
) else (
    echo No action required: %SystemRoot%\System32\drivers\WdNisDrv.sys is not found.
)
:: ----------------------------------------------------------


:: Disable Microsoft Defender Antivirus Mini-Filter Driver service
echo --- Disable Microsoft Defender Antivirus Mini-Filter Driver service
PowerShell -ExecutionPolicy Unrestricted -Command "$command = 'sc stop "^""WdFilter"^"" >nul & sc config "^""WdFilter"^"" start=disabled'; $trustedInstallerSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'); $trustedInstallerName = $trustedInstallerSid.Translate([System.Security.Principal.NTAccount]); $streamOutFile = New-TemporaryFile; $batchFile = New-TemporaryFile; try {; $batchFile = Rename-Item $batchFile "^""$($batchFile.BaseName).bat"^"" -PassThru; "^""@echo off`r`n$command`r`nexit 0"^"" | Out-File $batchFile -Encoding ASCII; $taskName = 'privacy.sexy invoke'; schtasks.exe /delete /tn "^""$taskName"^"" /f 2>&1 | Out-Null <# Clean if something went wrong before, suppress any output #>; $taskAction = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument "^""cmd /c `"^""$batchFile`"^"" > $streamOutFile 2>&1"^""; $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries; Register-ScheduledTask -TaskName $taskName -Action $taskAction -Settings $settings -Force -ErrorAction Stop | Out-Null; try {; ($scheduleService = New-Object -ComObject Schedule.Service).Connect(); $scheduleService.GetFolder('\').GetTask($taskName).RunEx($null, 0, 0, $trustedInstallerName) | Out-Null; $timeOutLimit = (Get-Date).AddMinutes(5); Write-Host "^""Running as $trustedInstallerName"^""; while((Get-ScheduledTaskInfo $taskName).LastTaskResult -eq 267009) {; Start-Sleep -Milliseconds 200; if((Get-Date) -gt $timeOutLimit) {; Write-Warning "^""Skipping results, it took so long to execute script."^""; break;; }; }; if (($result = (Get-ScheduledTaskInfo $taskName).LastTaskResult) -ne 0) {; Write-Error "^""Failed to execute with exit code: $result."^""; }; } finally {; schtasks.exe /delete /tn "^""$taskName"^"" /f | Out-Null <# Outputs only errors #>; }; Get-Content $streamOutFile; } finally {; Remove-Item $streamOutFile, $batchFile; }"
if exist "%SystemRoot%\System32\drivers\WdFilter.sys" (
    takeown /f "%SystemRoot%\System32\drivers\WdFilter.sys"
    icacls "%SystemRoot%\System32\drivers\WdFilter.sys" /grant administrators:F
    move "%SystemRoot%\System32\drivers\WdFilter.sys" "%SystemRoot%\System32\drivers\WdFilter.sys.OLD" && (
        echo Moved "%SystemRoot%\System32\drivers\WdFilter.sys" to "%SystemRoot%\System32\drivers\WdFilter.sys.OLD"
    ) || (
        echo Could not move %SystemRoot%\System32\drivers\WdFilter.sys 1>&2
    )
) else (
    echo No action required: %SystemRoot%\System32\drivers\WdFilter.sys is not found.
)
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -Disable Microsoft Defender Antivirus Boot Driver service-
:: ----------------------------------------------------------
echo --- Disable Microsoft Defender Antivirus Boot Driver service
PowerShell -ExecutionPolicy Unrestricted -Command "$command = 'sc stop "^""WdBoot"^"" >nul & sc config "^""WdBoot"^"" start=disabled'; $trustedInstallerSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'); $trustedInstallerName = $trustedInstallerSid.Translate([System.Security.Principal.NTAccount]); $streamOutFile = New-TemporaryFile; $batchFile = New-TemporaryFile; try {; $batchFile = Rename-Item $batchFile "^""$($batchFile.BaseName).bat"^"" -PassThru; "^""@echo off`r`n$command`r`nexit 0"^"" | Out-File $batchFile -Encoding ASCII; $taskName = 'privacy.sexy invoke'; schtasks.exe /delete /tn "^""$taskName"^"" /f 2>&1 | Out-Null <# Clean if something went wrong before, suppress any output #>; $taskAction = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument "^""cmd /c `"^""$batchFile`"^"" > $streamOutFile 2>&1"^""; $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries; Register-ScheduledTask -TaskName $taskName -Action $taskAction -Settings $settings -Force -ErrorAction Stop | Out-Null; try {; ($scheduleService = New-Object -ComObject Schedule.Service).Connect(); $scheduleService.GetFolder('\').GetTask($taskName).RunEx($null, 0, 0, $trustedInstallerName) | Out-Null; $timeOutLimit = (Get-Date).AddMinutes(5); Write-Host "^""Running as $trustedInstallerName"^""; while((Get-ScheduledTaskInfo $taskName).LastTaskResult -eq 267009) {; Start-Sleep -Milliseconds 200; if((Get-Date) -gt $timeOutLimit) {; Write-Warning "^""Skipping results, it took so long to execute script."^""; break;; }; }; if (($result = (Get-ScheduledTaskInfo $taskName).LastTaskResult) -ne 0) {; Write-Error "^""Failed to execute with exit code: $result."^""; }; } finally {; schtasks.exe /delete /tn "^""$taskName"^"" /f | Out-Null <# Outputs only errors #>; }; Get-Content $streamOutFile; } finally {; Remove-Item $streamOutFile, $batchFile; }"
if exist "%SystemRoot%\System32\drivers\WdBoot.sys" (
    takeown /f "%SystemRoot%\System32\drivers\WdBoot.sys"
    icacls "%SystemRoot%\System32\drivers\WdBoot.sys" /grant administrators:F
    move "%SystemRoot%\System32\drivers\WdBoot.sys" "%SystemRoot%\System32\drivers\WdBoot.sys.OLD" && (
        echo Moved "%SystemRoot%\System32\drivers\WdBoot.sys" to "%SystemRoot%\System32\drivers\WdBoot.sys.OLD"
    ) || (
        echo Could not move %SystemRoot%\System32\drivers\WdBoot.sys 1>&2
    )
) else (
    echo No action required: %SystemRoot%\System32\drivers\WdBoot.sys is not found.
)
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Disable SmartScreen for apps and files----------
:: ----------------------------------------------------------
echo --- Disable SmartScreen for apps and files
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d "0" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Disable SmartScreen in file explorer-----------
:: ----------------------------------------------------------
echo --- Disable SmartScreen in file explorer
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "Off" /f
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "Off" /f
:: ----------------------------------------------------------


:: Disable SmartScreen preventing users from running applications
echo --- Disable SmartScreen preventing users from running applications
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "ShellSmartScreenLevel" /t REG_SZ /d "Warn" /f
:: ----------------------------------------------------------


:: Prevent Chromium Edge SmartScreen from blocking potentially unwanted apps
echo --- Prevent Chromium Edge SmartScreen from blocking potentially unwanted apps
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "SmartScreenPuaEnabled" /t REG_DWORD /d "0" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Disable SmartScreen in Edge----------------
:: ----------------------------------------------------------
echo --- Disable SmartScreen in Edge
reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "PreventOverride" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v "PreventOverride" /t REG_DWORD /d "0" /f
:: For Microsoft Edge version 77 or later
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "SmartScreenEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "PreventSmartScreenPromptOverride" /t REG_DWORD /d "0" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Disable SmartScreen in Internet Explorer---------
:: ----------------------------------------------------------
echo --- Disable SmartScreen in Internet Explorer
reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0" /v "2301" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----Turn off SmartScreen App Install Control feature-----
:: ----------------------------------------------------------
echo --- Turn off SmartScreen App Install Control feature
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SmartScreen" /v "ConfigureAppInstallControl" /t REG_SZ /d "Anywhere" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SmartScreen" /v "ConfigureAppInstallControlEnabled" /t "REG_DWORD" /d "0" /f
:: ----------------------------------------------------------


:: Turn off SmartScreen to check web content (URLs) that apps use
echo --- Turn off SmartScreen to check web content (URLs) that apps use
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Disable lock screen app notifications-----------
:: ----------------------------------------------------------
echo --- Disable lock screen app notifications
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "DisableLockScreenAppNotifications" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------Disable online tips--------------------
:: ----------------------------------------------------------
echo --- Disable online tips
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "AllowOnlineTips" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Turn off Internet File Association service--------
:: ----------------------------------------------------------
echo --- Turn off Internet File Association service
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInternetOpenWith" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Turn off the "Order Prints" picture task---------
:: ----------------------------------------------------------
echo --- Turn off the "Order Prints" picture task
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoOnlinePrintsWizard" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----Disable the file and folder Publish to Web option-----
:: ----------------------------------------------------------
echo --- Disable the file and folder Publish to Web option
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoPublishingWizard" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---Prevent downloading a list of providers for wizards----
:: ----------------------------------------------------------
echo --- Prevent downloading a list of providers for wizards
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoWebServices" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Disable Live Tiles push notifications-----------
:: ----------------------------------------------------------
echo --- Disable Live Tiles push notifications
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoTileApplicationNotification" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------User Data Storage (UnistoreSvc) Service----------
:: ----------------------------------------------------------
echo --- User Data Storage (UnistoreSvc) Service
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceQuery = 'UnistoreSvc'; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceQuery -ErrorAction SilentlyContinue; if(!$service) {; Write-Host "^""Service query `"^""$serviceQuery`"^"" did not yield any results, no need to disable it."^""; Exit 0; }; $serviceName = $service.Name; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host "^""`"^""$serviceName`"^"" is running, trying to stop it."^""; try {; Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else {; Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if service info is not found in registry #>; $registryKey = "^""HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"^""; if(!(Test-Path $registryKey)) {; Write-Host "^""`"^""$registryKey`"^"" is not found in registry, cannot enable it."^""; Exit 0; }; <# -- 4. Skip if already disabled #>; if( $(Get-ItemProperty -Path "^""$registryKey"^"").Start -eq 4) {; Write-Host "^""`"^""$serviceName`"^"" is already disabled from start, no further action is needed."^""; Exit 0; }; <# -- 5. Disable service #>; try {; Set-ItemProperty $registryKey -Name Start -Value 4 -Force -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceQuery = 'UnistoreSvc_*'; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceQuery -ErrorAction SilentlyContinue; if(!$service) {; Write-Host "^""Service query `"^""$serviceQuery`"^"" did not yield any results, no need to disable it."^""; Exit 0; }; $serviceName = $service.Name; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host "^""`"^""$serviceName`"^"" is running, trying to stop it."^""; try {; Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else {; Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if service info is not found in registry #>; $registryKey = "^""HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"^""; if(!(Test-Path $registryKey)) {; Write-Host "^""`"^""$registryKey`"^"" is not found in registry, cannot enable it."^""; Exit 0; }; <# -- 4. Skip if already disabled #>; if( $(Get-ItemProperty -Path "^""$registryKey"^"").Start -eq 4) {; Write-Host "^""`"^""$serviceName`"^"" is already disabled from start, no further action is needed."^""; Exit 0; }; <# -- 5. Disable service #>; try {; Set-ItemProperty $registryKey -Name Start -Value 4 -Force -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Sync Host (OneSyncSvc) Service Service----------
:: ----------------------------------------------------------
echo --- Sync Host (OneSyncSvc) Service Service
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceQuery = 'OneSyncSvc'; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceQuery -ErrorAction SilentlyContinue; if(!$service) {; Write-Host "^""Service query `"^""$serviceQuery`"^"" did not yield any results, no need to disable it."^""; Exit 0; }; $serviceName = $service.Name; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host "^""`"^""$serviceName`"^"" is running, trying to stop it."^""; try {; Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else {; Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if service info is not found in registry #>; $registryKey = "^""HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"^""; if(!(Test-Path $registryKey)) {; Write-Host "^""`"^""$registryKey`"^"" is not found in registry, cannot enable it."^""; Exit 0; }; <# -- 4. Skip if already disabled #>; if( $(Get-ItemProperty -Path "^""$registryKey"^"").Start -eq 4) {; Write-Host "^""`"^""$serviceName`"^"" is already disabled from start, no further action is needed."^""; Exit 0; }; <# -- 5. Disable service #>; try {; Set-ItemProperty $registryKey -Name Start -Value 4 -Force -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceQuery = 'OneSyncSvc_*'; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceQuery -ErrorAction SilentlyContinue; if(!$service) {; Write-Host "^""Service query `"^""$serviceQuery`"^"" did not yield any results, no need to disable it."^""; Exit 0; }; $serviceName = $service.Name; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host "^""`"^""$serviceName`"^"" is running, trying to stop it."^""; try {; Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else {; Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if service info is not found in registry #>; $registryKey = "^""HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"^""; if(!(Test-Path $registryKey)) {; Write-Host "^""`"^""$registryKey`"^"" is not found in registry, cannot enable it."^""; Exit 0; }; <# -- 4. Skip if already disabled #>; if( $(Get-ItemProperty -Path "^""$registryKey"^"").Start -eq 4) {; Write-Host "^""`"^""$serviceName`"^"" is already disabled from start, no further action is needed."^""; Exit 0; }; <# -- 5. Disable service #>; try {; Set-ItemProperty $registryKey -Name Start -Value 4 -Force -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------------Xbox Live Auth Manager------------------
:: ----------------------------------------------------------
echo --- Xbox Live Auth Manager
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'XblAuthManager'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) {; Write-Host "^""Service `"^""$serviceName`"^"" could not be not found, no need to disable it."^""; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try {; Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else {; Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if(!$startupType) {; $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) {; $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if($startupType -eq 'Disabled') {; Write-Host "^""$serviceName is already disabled, no further action is needed"^""; }; <# -- 4. Disable service #>; try {; Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------Xbox Live Game Save--------------------
:: ----------------------------------------------------------
echo --- Xbox Live Game Save
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'XblGameSave'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) {; Write-Host "^""Service `"^""$serviceName`"^"" could not be not found, no need to disable it."^""; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try {; Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else {; Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if(!$startupType) {; $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) {; $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if($startupType -eq 'Disabled') {; Write-Host "^""$serviceName is already disabled, no further action is needed"^""; }; <# -- 4. Disable service #>; try {; Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Xbox Live Networking Service---------------
:: ----------------------------------------------------------
echo --- Xbox Live Networking Service
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'XboxNetApiSvc'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) {; Write-Host "^""Service `"^""$serviceName`"^"" could not be not found, no need to disable it."^""; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try {; Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else {; Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if(!$startupType) {; $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) {; $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if($startupType -eq 'Disabled') {; Write-Host "^""$serviceName is already disabled, no further action is needed"^""; }; <# -- 4. Disable service #>; try {; Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Delivery Optimization (P2P Windows Updates)--------
:: ----------------------------------------------------------
echo --- Delivery Optimization (P2P Windows Updates)
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceQuery = 'DoSvc'; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceQuery -ErrorAction SilentlyContinue; if(!$service) {; Write-Host "^""Service query `"^""$serviceQuery`"^"" did not yield any results, no need to disable it."^""; Exit 0; }; $serviceName = $service.Name; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host "^""`"^""$serviceName`"^"" is running, trying to stop it."^""; try {; Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else {; Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if service info is not found in registry #>; $registryKey = "^""HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"^""; if(!(Test-Path $registryKey)) {; Write-Host "^""`"^""$registryKey`"^"" is not found in registry, cannot enable it."^""; Exit 0; }; <# -- 4. Skip if already disabled #>; if( $(Get-ItemProperty -Path "^""$registryKey"^"").Start -eq 4) {; Write-Host "^""`"^""$serviceName`"^"" is already disabled from start, no further action is needed."^""; Exit 0; }; <# -- 5. Disable service #>; try {; Set-ItemProperty $registryKey -Name Start -Value 4 -Force -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------Downloaded Maps Manager------------------
:: ----------------------------------------------------------
echo --- Downloaded Maps Manager
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'MapsBroker'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) {; Write-Host "^""Service `"^""$serviceName`"^"" could not be not found, no need to disable it."^""; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try {; Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else {; Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if(!$startupType) {; $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) {; $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if($startupType -eq 'Disabled') {; Write-Host "^""$serviceName is already disabled, no further action is needed"^""; }; <# -- 4. Disable service #>; try {; Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------------Kill OneDrive process-------------------
:: ----------------------------------------------------------
echo --- Kill OneDrive process
taskkill /f /im OneDrive.exe
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------------Uninstall OneDrive--------------------
:: ----------------------------------------------------------
echo --- Uninstall OneDrive
if %PROCESSOR_ARCHITECTURE%==x86 (
    %SystemRoot%\System32\OneDriveSetup.exe /uninstall 2>nul
) else (
    %SystemRoot%\SysWOW64\OneDriveSetup.exe /uninstall 2>nul
)
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Remove OneDrive leftovers-----------------
:: ----------------------------------------------------------
echo --- Remove OneDrive leftovers
rd "%UserProfile%\OneDrive" /q /s
rd "%LocalAppData%\Microsoft\OneDrive" /q /s
rd "%ProgramData%\Microsoft OneDrive" /q /s
rd "%SystemDrive%\OneDriveTemp" /q /s
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Delete OneDrive shortcuts-----------------
:: ----------------------------------------------------------
echo --- Delete OneDrive shortcuts
del "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Microsoft OneDrive.lnk" /s /f /q
del "%APPDATA%\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" /s /f /q
del "%USERPROFILE%\Links\OneDrive.lnk" /s /f /q
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Disable usage of OneDrive-----------------
:: ----------------------------------------------------------
echo --- Disable usage of OneDrive
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /t REG_DWORD /v "DisableFileSyncNGSC" /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /t REG_DWORD /v "DisableFileSync" /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---Prevent automatic OneDrive install for current user----
:: ----------------------------------------------------------
echo --- Prevent automatic OneDrive install for current user
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----Prevent automatic OneDrive install for new users-----
:: ----------------------------------------------------------
echo --- Prevent automatic OneDrive install for new users
reg load "HKU\Default" "%SystemDrive%\Users\Default\NTUSER.DAT" 
reg delete "HKU\Default\software\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f
reg unload "HKU\Default"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Remove OneDrive from explorer menu------------
:: ----------------------------------------------------------
echo --- Remove OneDrive from explorer menu
reg delete "HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
reg delete "HKCR\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
reg add "HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v System.IsPinnedToNameSpaceTree /d "0" /t REG_DWORD /f
reg add "HKCR\Wow6432Node\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v System.IsPinnedToNameSpaceTree /d "0" /t REG_DWORD /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Delete all OneDrive related Services-----------
:: ----------------------------------------------------------
echo --- Delete all OneDrive related Services
for /f "tokens=1 delims=," %%x in ('schtasks /query /fo csv ^| find "OneDrive"') do schtasks /Delete /TN %%x /F
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Delete OneDrive path from registry------------
:: ----------------------------------------------------------
echo --- Delete OneDrive path from registry
reg delete "HKCU\Environment" /v "OneDrive" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------------Windows Search feature------------------
:: ----------------------------------------------------------
echo --- Windows Search feature
dism /Online /Disable-Feature /FeatureName:"SearchEngine-Client-Package" /NoRestart
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Uninstall Edge (chromium-based)--------------
:: ----------------------------------------------------------
echo --- Uninstall Edge (chromium-based)
PowerShell -ExecutionPolicy Unrestricted -Command "$installer = (Get-ChildItem "^""$env:ProgramFiles*\Microsoft\Edge\Application\*\Installer\setup.exe"^""); if (!$installer) {; Write-Host 'Could not find the installer'; } else {; & $installer.FullName -Uninstall -System-Level -Verbose-Logging -Force-Uninstall; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Remove Meet Now icon from taskbar-------------
:: ----------------------------------------------------------
echo --- Remove Meet Now icon from taskbar
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCAMeetNow" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Disable Reserved Storage for updates-----------
:: ----------------------------------------------------------
echo --- Disable Reserved Storage for updates
dism /online /Set-ReservedStorageState /State:Disabled /NoRestart
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" /v "MiscPolicyInfo" /t REG_DWORD /d "2" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" /v "ShippedWithReserves" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" /v "PassedPolicy" /t REG_DWORD /d "0" /f
:: ----------------------------------------------------------

