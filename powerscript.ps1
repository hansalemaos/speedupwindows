Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope LocalMachine
Set-ExecutionPolicy -ExecutionPolicy Unrestricted
echo " Restore Point"
Enable-ComputerRestore -Drive "C:\"
Checkpoint-Computer -Description "RestorePoint1" -RestorePointType "MODIFY_SETTINGS"


Add-Type -TypeDefinition @"
    using System;
    using System.Runtime.InteropServices;
    [StructLayout(LayoutKind.Sequential)] public struct ANIMATIONINFO {
        public uint cbSize;
        public bool iMinAnimate;
    }
    public class PInvoke { 
        [DllImport("user32.dll")] public static extern bool SystemParametersInfoW(uint uiAction, uint uiParam, ref ANIMATIONINFO pvParam, uint fWinIni);
    }
"@
$animInfo = New-Object ANIMATIONINFO
$animInfo.cbSize = 8
$animInfo.iMinAnimate = $args[0]
[PInvoke]::SystemParametersInfoW(0x49, 0, [ref]$animInfo, 3)



echo " high power "
# fill a hashtable with power scheme guids and alias names:

# Name                                   Value
# -----                                  -----
# 381b4222-f694-41f0-9685-ff5bb260df2e   SCHEME_BALANCED  # --> Balanced
# 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c   SCHEME_MIN       # --> High performance
# a1841308-3541-4fab-bc81-f71556f20b4a   SCHEME_MAX       # --> Power saver

$powerConstants = @{}
PowerCfg.exe -ALIASES | Where-Object { $_ -match 'SCHEME_' } | ForEach-Object {
    $guid,$alias = ($_ -split '\s+', 2).Trim()
    $powerConstants[$guid] = $alias
}

# get a list of power schemes
$powerSchemes = PowerCfg.exe -LIST | Where-Object { $_ -match '^Power Scheme' } | ForEach-Object {
    $guid = $_ -replace '.*GUID:\s*([-a-f0-9]+).*', '$1'
    [PsCustomObject]@{
        Name     = $_.Trim("* ") -replace '.*\(([^)]+)\)$', '$1'          # LOCALIZED !
        Alias    = $powerConstants[$guid]
        Guid     = $guid
        IsActive = $_ -match '\*$'
    }
}

# set a variable for the desired power scheme (in this case High performance)
$desiredScheme = $powerSchemes | Where-Object { $_.Alias -eq 'SCHEME_MIN' }

# get the currently active scheme
$PowerSettingsorg = $powerSchemes | Where-Object { $_.IsActive }
    # set powersettings to High Performance
    Powercfg.exe -SETACTIVE $desiredScheme.Alias  # you can also set this using the $desiredScheme.Guid
    # test if the setting has changed
    $currentPowerGuid = (Powercfg.exe -GETACTIVESCHEME) -replace '.*GUID:\s*([-a-f0-9]+).*', '$1'
    if ($currentPowerGuid -eq $desiredScheme.Guid) {
        Write-Host "++ Power plan Settings have changed to $($desiredScheme.Name).!"
    }
    else {
        # exit the script here???
        Throw "++ Power plan Settings did not change to $($desiredScheme.Name).!"
    }





echo " # Turn off the diagnostics tracking scheduled tasks"
ScheduledTasks -Disable

echo " # Disable the Windows features using the pop-up dialog box"
WindowsFeatures -Disable

echo " # Uninstall optional features using the pop-up dialog box"
WindowsCapabilities -Uninstall

echo " # Uninstall UWP apps using the pop-up dialog box"
UninstallUWPApps 

echo " # Disable the "Connected User Experiences and Telemetry" service (DiagTrack), and block the connection for the Unified Telemetry Client Outbound Traffic"
# Disabling the "Connected User Experiences and Telemetry" service (DiagTrack) can cause you not being able to get Xbox achievements anymore

echo " # Set the diagnostic data collection to minimum"
DiagnosticDataLevel -Minimal

echo " # Turn off the Windows Error Reporting"
ErrorReporting -Disable

echo " # Change the feedback frequency to "Never""
FeedbackFrequency -Never

echo " # Do not use sign-in info to automatically finish setting up device and reopen apps after an update or restart"
SigninInfo -Disable

echo " # Do not let websites provide locally relevant content by accessing language list"
LanguageListAccess -Disable

echo " # Do not allow apps to use advertising ID to make ads more interresting to you based on your app usage "
AdvertisingID -Disable

echo " # Hide the Windows welcome experiences after updates and occasionally when I sign in to highlight what's new and suggested"
WindowsWelcomeExperience -Hide

echo " # Do not get tips, tricks, and suggestions as you use Windows"
WindowsTips -Disable

echo " # Hide from me suggested content in the Settings app"
SettingsSuggestedContent -Hide

echo " # Turn off automatic installing suggested apps"
AppsSilentInstalling -Disable

echo " # Do not suggest ways I can finish setting up my device to get the most out of Windows"
WhatsNewInWindows -Disable

echo " # Do not let Microsoft offer you tailored expereinces based on the diagnostic data setting you have chosen"
TailoredExperiences -Disable

echo " # Disable Bing search in the Start Menu"
BingSearch -Disable

echo " # Show hidden files, folders, and drives"
HiddenItems -Enable

echo " # Show the file name extensions"
FileExtensions -Show

echo " # Show folder merge conflicts"
MergeConflicts -Show

echo " # Hide Cortana button on the taskbar"
CortanaButton -Hide

echo " # Do not show sync provider notification within File Explorer"
OneDriveFileExplorerAd -Hide

echo " # When I snap a window, do not show what I can snap next to it"
SnapAssist -Disable

echo " # Show the file transfer dialog box in the detailed mode"
FileTransferDialog -Detailed

echo " # Expand the File Explorer ribbon"
FileExplorerRibbon -Expanded

echo " # Display the recycle bin files delete confirmation dialog"
RecycleBinDeleteConfirmation -Enable

echo " # Hide recently used files in Quick access"
QuickAccessRecentFiles -Hide

echo " # Hide frequently used folders in Quick access"
QuickAccessFrequentFolders -Hide

echo " # Hide the search on the taskbar"
TaskbarSearch -Hide

echo " # Hide the Task View button on the taskbar"
TaskViewButton -Hide

echo " # Hide search highlights"
SearchHighlights -Hide

echo " # Hide People on the taskbar"
PeopleTaskbar -Hide

echo " # Hide seconds on the taskbar clock (default value)"
SecondsInSystemClock -Hide

echo " # Hide the Windows Ink Workspace button on the taskbar"
WindowsInkWorkspace -Hide

echo " # Hide all icons in the notification area (default value)"
NotificationAreaIcons -Hide

echo " # Hide the Meet Now icon in the notification area"
MeetNow -Hide

echo " # Disable "News and Interests" on the taskbar"
NewsInterests -Disable

echo " # Unpin the "Microsoft Edge", "Microsoft Store", or "Mail" shortcuts from the taskbar"
UnpinTaskbarShortcuts -Shortcuts Edge, Store, Mail

echo " # View the Control Panel icons by category (default value)"
ControlPanelView -Category

echo " # Hide the "New App Installed" indicator"
# Скрыть уведомление "Установлено новое приложение"

echo " # Hide first sign-in animation after the upgrade"
FirstLogonAnimation -Disable

echo " # Start Task Manager in the expanded mode"
TaskManagerWindow -Expanded

echo " # Show a notification when your PC requires a restart to finish updating"
RestartNotification -Show

echo " # Do not add the "- Shortcut" suffix to the file name of created shortcuts"
ShortcutsSuffix -Disable

echo " # Do not use a different input method for each app window (default value)"
AppsLanguageSwitch -Disable

echo " # When I grab a windows's title bar and shake it, minimize all other windows (default value)"
AeroShaking -Enable

echo " #region OneDrive"
# Uninstall OneDrive. The OneDrive user folder won't be removed

echo " # Turn on Storage Sense"
StorageSense -Enable

echo " # Run Storage Sense every month"
StorageSenseFrequency -Month

echo " # Delete temporary files that apps aren't using"
StorageSenseTempFiles -Enable

echo " # Disable hibernation. Do not recommend turning it off on laptops"
Hibernation -Disable

echo " # Disable the Windows 260 characters path limit"
Win32LongPathLimit -Disable

echo " # Display the Stop error information on the BSoD"
BSoDStopError -Enable

echo " # Choose when to be notified about changes to your computer: never notify"
AdminApprovalMode -Never

echo " # Turn on access to mapped drives from app running with elevated permissions with Admin Approval Mode enabled"
MappedDrivesAppElevatedAccess -Enable

echo " # Turn off Delivery Optimization"
DeliveryOptimization -Disable

echo " # Always wait for the network at computer startup and logon for workgroup networks"
WaitNetworkStartup -Enable

echo " # Do not allow the computer to turn off the network adapters to save power"
NetworkAdaptersSavePower -Disable

echo " # Disable the Internet Protocol Version 6 (TCP/IPv6) component for all network connections"
IPv6Component -Disable

echo " # Save screenshots by pressing Win+PrtScr on the Desktop"
WinPrtScrFolder -Desktop

echo " # Launch folder windows in a separate process"
FoldersLaunchSeparateProcess -Enable

echo " # Disable and delete reserved storage after the next update installation"
ReservedStorage -Disable

echo " # Disable help lookup via F1"
F1HelpPage -Disable

echo " # Enable Num Lock at startup"
NumLock -Enable

echo " # Do not allow the shortcut key to Start Sticky Keys by pressing the the Shift key 5 times"
StickyShift -Disable

echo " # Don't use AutoPlay for all media and devices"
Autoplay -Disable

echo " # Enable thumbnail cache removal (default value)"
ThumbnailCacheRemoval -Enable

echo " # Turn off automatically saving my restartable apps when signing out and restart them after signing in (default value)"
SaveRestartableApps -Disable

echo " # Enable "Network Discovery" and "File and Printers Sharing" for workgroup networks"
NetworkDiscovery -Enable

echo " # Uninstall the "PC Health Check" app and prevent it from installing in the future"
UninstallPCHealthCheck

echo " # Hide recently added apps in the Start menu"
RecentlyAddedApps -Hide

echo " # Hide app suggestions in the Start menu"
AppSuggestions -Hide

echo " # Run the Windows PowerShell shortcut from the Start menu as Administrator"
RunPowerShellShortcut -Elevated

echo " # Unpin all the Start tiles"
PinToStart -UnpinAll

echo " # Disable Cortana autostarting"
CortanaAutostart -Disable

echo " # Do not let UWP apps run in the background"
BackgroundUWPApps -Disable

echo " # Check for UWP apps updates"
CheckUWPAppsUpdates

echo " # Disable Xbox Game Bar"
XboxGameBar -Disable

echo " # Disable Xbox Game Bar tips"
XboxGameTips -Disable

echo " # Turn on hardware-accelerated GPU scheduling. Restart needed"
GPUScheduling -Enable

echo " # Create the "Windows Cleanup" scheduled task for cleaning up Windows unused files and updates"
# A native interactive toast notification pops up every 30 days. The task runs every 30 days

echo " # Create the "SoftwareDistribution" scheduled task for cleaning up the %SystemRoot%\SoftwareDistribution\Download folder"
# The task will wait until the Windows Updates service finishes running. The task runs every 90 days

echo " # Create the "Temp" scheduled task for cleaning up the %TEMP% folder"
# Only files older than one day will be deleted. The task runs every 60 days

echo " # Disable Microsoft Defender Exploit Guard network protection (default value)"
NetworkProtection -Disable

echo " # Disable detection for potentially unwanted applications and block them (default value)"
PUAppsDetection -Disable

echo " # Disable sandboxing for Microsoft Defender (default value)"
DefenderSandbox -Disable

echo " # Dismiss Microsoft Defender offer in the Windows Security about signing in Microsoft account"
DismissMSAccount

echo " # Dismiss Microsoft Defender offer in the Windows Security about turning on the SmartScreen filter for Microsoft Edge"
DismissSmartScreenFilter

echo " # Enable events auditing generated when a process is created (starts)"
AuditProcess -Enable

echo " # Include command line in process creation events"
CommandLineProcessAudit -Enable

echo " # Create the "Process Creation" сustom view in the Event Viewer to log executed processes and their arguments"
EventViewerCustomView -Enable

echo " # Microsoft Defender SmartScreen doesn't marks downloaded files from the Internet as unsafe"
AppsSmartScreen -Disable

echo " # Disable the Attachment Manager marking files that have been downloaded from the Internet as unsafe"
SaveZoneInformation -Disable

echo " # Disable Windows Sandbox (default value)"
WindowsSandbox -Disable

echo " # Show the "Extract all" item in the Windows Installer (.msi) context menu"
MSIExtractContext -Show

echo " # Show the "Install" item in the Cabinet (.cab) filenames extensions context menu"
CABInstallContext -Show

echo " # Hide the "Run as different user" item from the .exe filename extensions context menu (default value)"
RunAsDifferentUserContext -Hide

echo " # Hide the "Cast to Device" item from the media files and folders context menu"
CastToDeviceContext -Hide

echo " # Enable the "Open", "Print", and "Edit" context menu items for more than 15 items selected"
MultipleInvokeContext -Enable

echo " # Hide the "Look for an app in the Microsoft Store" item in the "Open with" dialog"
UseStoreOpenWith -Hide

Write-Host "Running the Batch Script Now..."
& .\privacy.bat

Write-Host "Running the Batch Script Now..."
& .\avast.exe