# AppLocker Hardening Tool by Hazy
# Fixed Version
# ===========================================================
# INITIAL SETUP
# ===========================================================
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing


$form = New-Object Windows.Forms.Form
$form.Width = 420
$form.Height = 460
$form.FormBorderStyle = 'None'
$form.StartPosition = 'CenterScreen'
$form.TopMost = $true
$form.BackColor = 'Black'


Start-Sleep -Seconds 2
$form.Close()

# ===========================================================
# ========== ASCII UI SEPARATORS AND SPINNER FUNCTION ==========
# ===========================================================

function Show-Spinner {
    param (
        [string]$Message = "Working...",
        [int]$Duration = 5
    )
    $spinner = "|/-\"
    for ($i = 0; $i -lt $Duration * 10; $i++) {
        $char = $spinner[$i % $spinner.Length]
        Write-Host -NoNewline "`r$Message $char"
        Start-Sleep -Milliseconds 100
    }
    Write-Host "`r$Message Done.`n"
}

function Write-SectionHeader {
    param (
        [string]$Title
    )
    Write-Host "`n====================================================================================================" -ForegroundColor DarkGray
    Write-Host "           $Title" -ForegroundColor White
    Write-Host "====================================================================================================" -ForegroundColor DarkGray
}

# Check for admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "WARNING: This script requires administrative privileges to properly configure AppLocker." -ForegroundColor Red
    Write-Host "Please run this script as Administrator." -ForegroundColor Red
    Write-Host "Press any key to continue anyway (some functions may not work)..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}
# Global mode: "AuditOnly" or "Enabled"
$EnforcementMode = "AuditOnly"


# Import AppLocker module
if (!(Get-Module -Name AppLocker -ErrorAction SilentlyContinue)) {
    try {
        Import-Module AppLocker -ErrorAction Stop
        Write-Host "AppLocker module loaded successfully." -ForegroundColor Green
    } catch {
        Write-Host "WARNING: Failed to load AppLocker module. Some functions may not work." -ForegroundColor Red
        Write-Host "Error: $_" -ForegroundColor Red
    }
}

$logDir = "logs"
$policyDir = "GeneratedPolicies"
$rulesDir = "RuleFiles"
$backupDir = "backup"
$profileDir = "Applocker-Profiles"

foreach ($dir in @($logDir, $policyDir, $rulesDir, $backupDir)) {
    if (!(Test-Path -Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
}

$logPath = "$logDir\hardening-log.txt"

function Write-Log {
    param ($Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $logPath -Value "[$timestamp] $Message"
    Write-Host $Message
}

# ===========================================================
# DEFINE RULES IN SCRIPT
# ===========================================================

$BuiltInRules = @{
    'Rule1' = @(
@{ Type = 'Exe'; Xml = @"
    <FilePathRule Id="00000000-0000-0000-0000-000000000001" Name="Block Tasks" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Tasks\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000003" Name="Block Tracing" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Tracing\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000005" Name="Block Servicing Sessions" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\servicing\Sessions\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000007" Name="Block CRMLog" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Registration\CRMLog\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000009" Name="Block Dlna DeviceIcon" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\ServiceProfiles\LocalService\AppData\Local\Microsoft\Dlna\DeviceIcon\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000011" Name="Block MachineKeys" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\Microsoft\Crypto\RSA\MachineKeys\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000013" Name="Block SysWOW64 FxsTmp" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\SysWOW64\FxsTmp\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000015" Name="Block SysWOW64 Tasks" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\SysWOW64\Tasks\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000017" Name="Block SysWOW64 com dmp" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\SysWOW64\com\dmp\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000019" Name="Block OpsMgrTrace" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Logs\OpsMgrTrace\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000021" Name="Block Servicing Packages" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\servicing\Packages\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000025" Name="Block Temp" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Temp\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000027" Name="Block FxsTmp" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\FxsTmp\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000029" Name="Block System32 Tasks" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\Tasks\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000031" Name="Block System32 com dmp" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\com\dmp\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000033" Name="Block DriverData" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\Drivers\DriverData\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000035" Name="Block Printers" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\spool\PRINTERS\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000037" Name="Block Servers" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\spool\SERVERS\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000039" Name="Block Color Drivers" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\spool\drivers\color\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000041" Name="Block SyncCenter" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\Tasks\Microsoft\Windows\SyncCenter\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000043" Name="Block SysWOW64 SyncCenter" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\SysWOW64\Tasks\Microsoft\Windows\SyncCenter\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000045" Name="Block SysWOW64 PLA System" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\SysWOW64\Tasks\Microsoft\Windows\PLA\System\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000053" Name="Block WIA debug" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\debug\WIA\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000055" Name="Block Event Logs" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\winevt\Logs\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000057" Name="Block CCM Logs" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\ccm\logs\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000059" Name="Block AppVTempData" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\ccm\systemtemp\appvtempdata\appvcommandoutput\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000061" Name="Block NoIDMIFs" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\ccm\inventory\noidmifs\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000065" Name="Block Catroot2" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\catroot2\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000067" Name="Mitigating VSTO Add-ins Risks 1" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%LOCALAPPDATA%\Apps\2.0\" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000069" Name="Mitigating VSTO Add-ins Risks 2" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%USERPROFILE%\AppData\Local\assembly\" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000070" Name="Mitigating VSTO Add-ins Risks 2 ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%USERPROFILE%\AppData\Local\assembly:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000071" Name="Mitigating VSTO Add-ins Risks 3" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%USERPROFILE%\AppData\Local\Apps\2.0\" />
      </Conditions>
    </FilePathRule>

   
    

"@ },
@{ Type = 'Script'; Xml = @"
    <FilePathRule Id="00000000-0000-0000-0000-000000000001" Name="Block Tasks" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Tasks\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000003" Name="Block Tracing" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Tracing\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000005" Name="Block Servicing Sessions" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\servicing\Sessions\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000007" Name="Block CRMLog" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Registration\CRMLog\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000009" Name="Block Dlna DeviceIcon" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\ServiceProfiles\LocalService\AppData\Local\Microsoft\Dlna\DeviceIcon\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000011" Name="Block MachineKeys" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\Microsoft\Crypto\RSA\MachineKeys\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000013" Name="Block SysWOW64 FxsTmp" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\SysWOW64\FxsTmp\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000015" Name="Block SysWOW64 Tasks" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\SysWOW64\Tasks\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000017" Name="Block SysWOW64 com dmp" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\SysWOW64\com\dmp\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000019" Name="Block OpsMgrTrace" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Logs\OpsMgrTrace\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000021" Name="Block Servicing Packages" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\servicing\Packages\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000025" Name="Block Temp" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Temp\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000027" Name="Block FxsTmp" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\FxsTmp\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000029" Name="Block System32 Tasks" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\Tasks\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000031" Name="Block System32 com dmp" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\com\dmp\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000033" Name="Block DriverData" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\Drivers\DriverData\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000035" Name="Block Printers" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\spool\PRINTERS\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000037" Name="Block Servers" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\spool\SERVERS\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000039" Name="Block Color Drivers" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\spool\drivers\color\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000041" Name="Block SyncCenter" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\Tasks\Microsoft\Windows\SyncCenter\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000043" Name="Block SysWOW64 SyncCenter" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\SysWOW64\Tasks\Microsoft\Windows\SyncCenter\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000045" Name="Block SysWOW64 PLA System" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\SysWOW64\Tasks\Microsoft\Windows\PLA\System\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000053" Name="Block WIA debug" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\debug\WIA\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000055" Name="Block Event Logs" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\winevt\Logs\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000057" Name="Block CCM Logs" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\ccm\logs\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000059" Name="Block AppVTempData" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\ccm\systemtemp\appvtempdata\appvcommandoutput\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000061" Name="Block NoIDMIFs" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\ccm\inventory\noidmifs\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000065" Name="Block Catroot2" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\catroot2\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000067" Name="Mitigating VSTO Add-ins Risks 1" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%LOCALAPPDATA%\Apps\2.0\" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000069" Name="Mitigating VSTO Add-ins Risks 2" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%USERPROFILE%\AppData\Local\assembly\" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000070" Name="Mitigating VSTO Add-ins Risks 2 ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%USERPROFILE%\AppData\Local\assembly:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000071" Name="Mitigating VSTO Add-ins Risks 3" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%USERPROFILE%\AppData\Local\Apps\2.0\" />
      </Conditions>
    </FilePathRule>

   
    
"@ },
@{ Type = 'Msi'; Xml = @"
    <FilePathRule Id="00000000-0000-0000-0000-000000000001" Name="Block Tasks" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Tasks\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000003" Name="Block Tracing" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Tracing\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000005" Name="Block Servicing Sessions" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\servicing\Sessions\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000007" Name="Block CRMLog" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Registration\CRMLog\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000009" Name="Block Dlna DeviceIcon" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\ServiceProfiles\LocalService\AppData\Local\Microsoft\Dlna\DeviceIcon\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000011" Name="Block MachineKeys" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\Microsoft\Crypto\RSA\MachineKeys\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000013" Name="Block SysWOW64 FxsTmp" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\SysWOW64\FxsTmp\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000015" Name="Block SysWOW64 Tasks" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\SysWOW64\Tasks\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000017" Name="Block SysWOW64 com dmp" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\SysWOW64\com\dmp\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000019" Name="Block OpsMgrTrace" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Logs\OpsMgrTrace\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000021" Name="Block Servicing Packages" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\servicing\Packages\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000025" Name="Block Temp" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Temp\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000027" Name="Block FxsTmp" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\FxsTmp\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000029" Name="Block System32 Tasks" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\Tasks\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000031" Name="Block System32 com dmp" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\com\dmp\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000033" Name="Block DriverData" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\Drivers\DriverData\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000035" Name="Block Printers" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\spool\PRINTERS\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000037" Name="Block Servers" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\spool\SERVERS\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000039" Name="Block Color Drivers" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\spool\drivers\color\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000041" Name="Block SyncCenter" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\Tasks\Microsoft\Windows\SyncCenter\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000043" Name="Block SysWOW64 SyncCenter" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\SysWOW64\Tasks\Microsoft\Windows\SyncCenter\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000045" Name="Block SysWOW64 PLA System" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\SysWOW64\Tasks\Microsoft\Windows\PLA\System\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000053" Name="Block WIA debug" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\debug\WIA\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000055" Name="Block Event Logs" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\winevt\Logs\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000057" Name="Block CCM Logs" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\ccm\logs\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000059" Name="Block AppVTempData" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\ccm\systemtemp\appvtempdata\appvcommandoutput\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000061" Name="Block NoIDMIFs" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\ccm\inventory\noidmifs\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000065" Name="Block Catroot2" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\catroot2\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000067" Name="Mitigating VSTO Add-ins Risks 1" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%LOCALAPPDATA%\Apps\2.0\" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000069" Name="Mitigating VSTO Add-ins Risks 2" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%USERPROFILE%\AppData\Local\assembly\" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000070" Name="Mitigating VSTO Add-ins Risks 2 ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%USERPROFILE%\AppData\Local\assembly:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000071" Name="Mitigating VSTO Add-ins Risks 3" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%USERPROFILE%\AppData\Local\Apps\2.0\" />
      </Conditions>
    </FilePathRule>

"@ },
@{ Type = 'Appx'; Xml = @"
    <FilePathRule Id="00000000-0000-0000-0000-000000000001" Name="Block Tasks" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Tasks\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000003" Name="Block Tracing" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Tracing\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000005" Name="Block Servicing Sessions" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\servicing\Sessions\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000007" Name="Block CRMLog" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Registration\CRMLog\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000009" Name="Block Dlna DeviceIcon" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\ServiceProfiles\LocalService\AppData\Local\Microsoft\Dlna\DeviceIcon\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000011" Name="Block MachineKeys" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\Microsoft\Crypto\RSA\MachineKeys\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000013" Name="Block SysWOW64 FxsTmp" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\SysWOW64\FxsTmp\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000015" Name="Block SysWOW64 Tasks" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\SysWOW64\Tasks\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000017" Name="Block SysWOW64 com dmp" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\SysWOW64\com\dmp\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000019" Name="Block OpsMgrTrace" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Logs\OpsMgrTrace\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000021" Name="Block Servicing Packages" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\servicing\Packages\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000025" Name="Block Temp" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Temp\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000027" Name="Block FxsTmp" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\FxsTmp\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000029" Name="Block System32 Tasks" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\Tasks\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000031" Name="Block System32 com dmp" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\com\dmp\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000033" Name="Block DriverData" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\Drivers\DriverData\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000035" Name="Block Printers" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\spool\PRINTERS\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000037" Name="Block Servers" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\spool\SERVERS\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000039" Name="Block Color Drivers" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\spool\drivers\color\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000041" Name="Block SyncCenter" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\Tasks\Microsoft\Windows\SyncCenter\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000043" Name="Block SysWOW64 SyncCenter" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\SysWOW64\Tasks\Microsoft\Windows\SyncCenter\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000045" Name="Block SysWOW64 PLA System" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\SysWOW64\Tasks\Microsoft\Windows\PLA\System\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000053" Name="Block WIA debug" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\debug\WIA\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000055" Name="Block Event Logs" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\winevt\Logs\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000057" Name="Block CCM Logs" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\ccm\logs\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000059" Name="Block AppVTempData" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\ccm\systemtemp\appvtempdata\appvcommandoutput\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000061" Name="Block NoIDMIFs" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\ccm\inventory\noidmifs\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000065" Name="Block Catroot2" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\catroot2\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000067" Name="Mitigating VSTO Add-ins Risks 1" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%LOCALAPPDATA%\Apps\2.0\" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000069" Name="Mitigating VSTO Add-ins Risks 2" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%USERPROFILE%\AppData\Local\assembly\" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000070" Name="Mitigating VSTO Add-ins Risks 2 ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%USERPROFILE%\AppData\Local\assembly:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000071" Name="Mitigating VSTO Add-ins Risks 3" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%USERPROFILE%\AppData\Local\Apps\2.0\" />
      </Conditions>
    </FilePathRule>

"@ },
@{ Type = 'Dll'; Xml = @"
    <FilePathRule Id="00000000-0000-0000-0000-000000000001" Name="Block Tasks" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Tasks\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000003" Name="Block Tracing" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Tracing\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000005" Name="Block Servicing Sessions" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\servicing\Sessions\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000007" Name="Block CRMLog" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Registration\CRMLog\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000009" Name="Block Dlna DeviceIcon" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\ServiceProfiles\LocalService\AppData\Local\Microsoft\Dlna\DeviceIcon\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000011" Name="Block MachineKeys" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\Microsoft\Crypto\RSA\MachineKeys\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000013" Name="Block SysWOW64 FxsTmp" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\SysWOW64\FxsTmp\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000015" Name="Block SysWOW64 Tasks" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\SysWOW64\Tasks\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000017" Name="Block SysWOW64 com dmp" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\SysWOW64\com\dmp\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000019" Name="Block OpsMgrTrace" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Logs\OpsMgrTrace\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000021" Name="Block Servicing Packages" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\servicing\Packages\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000025" Name="Block Temp" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Temp\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000027" Name="Block FxsTmp" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\FxsTmp\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000029" Name="Block System32 Tasks" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\Tasks\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000031" Name="Block System32 com dmp" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\com\dmp\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000033" Name="Block DriverData" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\Drivers\DriverData\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000035" Name="Block Printers" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\spool\PRINTERS\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000037" Name="Block Servers" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\spool\SERVERS\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000039" Name="Block Color Drivers" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\spool\drivers\color\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000041" Name="Block SyncCenter" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\Tasks\Microsoft\Windows\SyncCenter\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000043" Name="Block SysWOW64 SyncCenter" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\SysWOW64\Tasks\Microsoft\Windows\SyncCenter\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000045" Name="Block SysWOW64 PLA System" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\SysWOW64\Tasks\Microsoft\Windows\PLA\System\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000053" Name="Block WIA debug" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\debug\WIA\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000055" Name="Block Event Logs" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\winevt\Logs\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000057" Name="Block CCM Logs" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\ccm\logs\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000059" Name="Block AppVTempData" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\ccm\systemtemp\appvtempdata\appvcommandoutput\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000061" Name="Block NoIDMIFs" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\ccm\inventory\noidmifs\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000065" Name="Block Catroot2" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\catroot2\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000067" Name="Mitigating VSTO Add-ins Risks 1" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%LOCALAPPDATA%\Apps\2.0\" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000069" Name="Mitigating VSTO Add-ins Risks 2" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%USERPROFILE%\AppData\Local\assembly\" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000070" Name="Mitigating VSTO Add-ins Risks 2 ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%USERPROFILE%\AppData\Local\assembly:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000071" Name="Mitigating VSTO Add-ins Risks 3" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%USERPROFILE%\AppData\Local\Apps\2.0\" />
      </Conditions>
    </FilePathRule>
"@ }
    );

    'Rule2' = @(
@{ Type = 'Exe'; Xml = @"
    <FilePathRule Id="00000000-0000-0000-0000-000000000002" Name="Block Tasks ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Tasks:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000004" Name="Block Tracing ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Tracing:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000006" Name="Block Servicing Sessions ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\servicing\Sessions:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000008" Name="Block CRMLog ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Registration\CRMLog:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000010" Name="Block Dlna DeviceIcon ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\ServiceProfiles\LocalService\AppData\Local\Microsoft\Dlna\DeviceIcon:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000012" Name="Block MachineKeys ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\Microsoft\Crypto\RSA\MachineKeys:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000014" Name="Block SysWOW64 FxsTmp ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\SysWOW64\FxsTmp:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000016" Name="Block SysWOW64 Tasks ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\SysWOW64\Tasks:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000018" Name="Block SysWOW64 com dmp ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\SysWOW64\com\dmp:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000020" Name="Block OpsMgrTrace ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Logs\OpsMgrTrace:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000022" Name="Block Servicing Packages ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\servicing\Packages:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000024" Name="Block Temp ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Temp:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000026" Name="Block Temp ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Temp:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000028" Name="Block FxsTmp ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\FxsTmp:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000030" Name="Block System32 Tasks ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\Tasks:*" />
      </Conditions>
    </FilePathRule>
     <FilePathRule Id="00000000-0000-0000-0000-000000000032" Name="Block System32 com dmp ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\com\dmp:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000034" Name="Block DriverData ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\Drivers\DriverData:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000036" Name="Block Printers ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\spool\PRINTERS:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000038" Name="Block Servers ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\spool\SERVERS:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000040" Name="Block Color Drivers ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\spool\drivers\color:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000042" Name="Block SyncCenter ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\Tasks\Microsoft\Windows\SyncCenter:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000044" Name="Block SysWOW64 SyncCenter ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\SysWOW64\Tasks\Microsoft\Windows\SyncCenter:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000046" Name="Block SysWOW64 PLA System ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\SysWOW64\Tasks\Microsoft\Windows\PLA\System:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000048" Name="Block C logs ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="C:\logs:*" />
      </Conditions>
    </FilePathRule>
     <FilePathRule Id="00000000-0000-0000-0000-000000000050" Name="Block User Downloads ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%USERPROFILE%\Downloads:*" />
      </Conditions>
    </FilePathRule>
     <FilePathRule Id="00000000-0000-0000-0000-000000000052" Name="Block AppLocker ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\AppLocker:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000054" Name="Block WIA debug ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\debug\WIA:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000056" Name="Block Event Logs ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\winevt\Logs:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000058" Name="Block CCM Logs ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\ccm\logs:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000060" Name="Block AppVTempData ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\ccm\systemtemp\appvtempdata\appvcommandoutput:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000062" Name="Block NoIDMIFs ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\ccm\inventory\noidmifs:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000066" Name="Block Catroot2 ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\catroot2\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000068" Name="Mitigating VSTO Add-ins Risks 1 ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%LOCALAPPDATA%\Apps\2.0:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000070" Name="Mitigating VSTO Add-ins Risks 2 ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%USERPROFILE%\AppData\Local\assembly:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000072" Name="Mitigating VSTO Add-ins Risks 3 ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%USERPROFILE%\AppData\Local\Apps\2.0:*" />
      </Conditions>
    </FilePathRule>
"@ },
@{ Type = 'Script'; Xml = @"
    <FilePathRule Id="00000000-0000-0000-0000-000000000002" Name="Block Tasks ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Tasks:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000004" Name="Block Tracing ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Tracing:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000006" Name="Block Servicing Sessions ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\servicing\Sessions:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000008" Name="Block CRMLog ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Registration\CRMLog:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000010" Name="Block Dlna DeviceIcon ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\ServiceProfiles\LocalService\AppData\Local\Microsoft\Dlna\DeviceIcon:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000012" Name="Block MachineKeys ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\Microsoft\Crypto\RSA\MachineKeys:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000014" Name="Block SysWOW64 FxsTmp ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\SysWOW64\FxsTmp:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000016" Name="Block SysWOW64 Tasks ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\SysWOW64\Tasks:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000018" Name="Block SysWOW64 com dmp ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\SysWOW64\com\dmp:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000020" Name="Block OpsMgrTrace ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Logs\OpsMgrTrace:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000022" Name="Block Servicing Packages ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\servicing\Packages:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000024" Name="Block Temp ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Temp:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000026" Name="Block Temp ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Temp:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000028" Name="Block FxsTmp ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\FxsTmp:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000030" Name="Block System32 Tasks ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\Tasks:*" />
      </Conditions>
    </FilePathRule>
     <FilePathRule Id="00000000-0000-0000-0000-000000000032" Name="Block System32 com dmp ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\com\dmp:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000034" Name="Block DriverData ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\Drivers\DriverData:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000036" Name="Block Printers ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\spool\PRINTERS:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000038" Name="Block Servers ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\spool\SERVERS:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000040" Name="Block Color Drivers ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\spool\drivers\color:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000042" Name="Block SyncCenter ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\Tasks\Microsoft\Windows\SyncCenter:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000044" Name="Block SysWOW64 SyncCenter ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\SysWOW64\Tasks\Microsoft\Windows\SyncCenter:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000046" Name="Block SysWOW64 PLA System ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\SysWOW64\Tasks\Microsoft\Windows\PLA\System:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000048" Name="Block C logs ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="C:\logs:*" />
      </Conditions>
    </FilePathRule>
     <FilePathRule Id="00000000-0000-0000-0000-000000000050" Name="Block User Downloads ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%USERPROFILE%\Downloads:*" />
      </Conditions>
    </FilePathRule>
     <FilePathRule Id="00000000-0000-0000-0000-000000000052" Name="Block AppLocker ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\AppLocker:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000054" Name="Block WIA debug ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\debug\WIA:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000056" Name="Block Event Logs ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\winevt\Logs:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000058" Name="Block CCM Logs ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\ccm\logs:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000060" Name="Block AppVTempData ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\ccm\systemtemp\appvtempdata\appvcommandoutput:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000062" Name="Block NoIDMIFs ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\ccm\inventory\noidmifs:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000066" Name="Block Catroot2 ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\catroot2\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000068" Name="Mitigating VSTO Add-ins Risks 1 ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%LOCALAPPDATA%\Apps\2.0:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000070" Name="Mitigating VSTO Add-ins Risks 2 ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%USERPROFILE%\AppData\Local\assembly:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000072" Name="Mitigating VSTO Add-ins Risks 3 ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%USERPROFILE%\AppData\Local\Apps\2.0:*" />
      </Conditions>
    </FilePathRule>

"@ },
@{ Type = 'Appx'; Xml = @" 
    <FilePathRule Id="00000000-0000-0000-0000-000000000002" Name="Block Tasks ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Tasks:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000004" Name="Block Tracing ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Tracing:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000006" Name="Block Servicing Sessions ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\servicing\Sessions:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000008" Name="Block CRMLog ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Registration\CRMLog:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000010" Name="Block Dlna DeviceIcon ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\ServiceProfiles\LocalService\AppData\Local\Microsoft\Dlna\DeviceIcon:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000012" Name="Block MachineKeys ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\Microsoft\Crypto\RSA\MachineKeys:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000014" Name="Block SysWOW64 FxsTmp ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\SysWOW64\FxsTmp:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000016" Name="Block SysWOW64 Tasks ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\SysWOW64\Tasks:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000018" Name="Block SysWOW64 com dmp ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\SysWOW64\com\dmp:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000020" Name="Block OpsMgrTrace ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Logs\OpsMgrTrace:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000022" Name="Block Servicing Packages ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\servicing\Packages:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000024" Name="Block Temp ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Temp:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000026" Name="Block Temp ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Temp:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000028" Name="Block FxsTmp ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\FxsTmp:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000030" Name="Block System32 Tasks ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\Tasks:*" />
      </Conditions>
    </FilePathRule>
     <FilePathRule Id="00000000-0000-0000-0000-000000000032" Name="Block System32 com dmp ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\com\dmp:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000034" Name="Block DriverData ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\Drivers\DriverData:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000036" Name="Block Printers ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\spool\PRINTERS:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000038" Name="Block Servers ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\spool\SERVERS:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000040" Name="Block Color Drivers ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\spool\drivers\color:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000042" Name="Block SyncCenter ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\Tasks\Microsoft\Windows\SyncCenter:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000044" Name="Block SysWOW64 SyncCenter ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\SysWOW64\Tasks\Microsoft\Windows\SyncCenter:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000046" Name="Block SysWOW64 PLA System ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\SysWOW64\Tasks\Microsoft\Windows\PLA\System:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000048" Name="Block C logs ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="C:\logs:*" />
      </Conditions>
    </FilePathRule>
     <FilePathRule Id="00000000-0000-0000-0000-000000000050" Name="Block User Downloads ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%USERPROFILE%\Downloads:*" />
      </Conditions>
    </FilePathRule>
     <FilePathRule Id="00000000-0000-0000-0000-000000000052" Name="Block AppLocker ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\AppLocker:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000054" Name="Block WIA debug ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\debug\WIA:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000056" Name="Block Event Logs ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\winevt\Logs:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000058" Name="Block CCM Logs ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\ccm\logs:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000060" Name="Block AppVTempData ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\ccm\systemtemp\appvtempdata\appvcommandoutput:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000062" Name="Block NoIDMIFs ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\ccm\inventory\noidmifs:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000066" Name="Block Catroot2 ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\catroot2\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000068" Name="Mitigating VSTO Add-ins Risks 1 ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%LOCALAPPDATA%\Apps\2.0:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000070" Name="Mitigating VSTO Add-ins Risks 2 ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%USERPROFILE%\AppData\Local\assembly:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000072" Name="Mitigating VSTO Add-ins Risks 3 ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%USERPROFILE%\AppData\Local\Apps\2.0:*" />
      </Conditions>
    </FilePathRule>
"@ },   
@{ Type = 'Dll'; Xml = @" 
    <FilePathRule Id="00000000-0000-0000-0000-000000000002" Name="Block Tasks ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Tasks:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000004" Name="Block Tracing ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Tracing:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000006" Name="Block Servicing Sessions ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\servicing\Sessions:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000008" Name="Block CRMLog ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Registration\CRMLog:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000010" Name="Block Dlna DeviceIcon ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\ServiceProfiles\LocalService\AppData\Local\Microsoft\Dlna\DeviceIcon:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000012" Name="Block MachineKeys ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\Microsoft\Crypto\RSA\MachineKeys:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000014" Name="Block SysWOW64 FxsTmp ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\SysWOW64\FxsTmp:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000016" Name="Block SysWOW64 Tasks ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\SysWOW64\Tasks:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000018" Name="Block SysWOW64 com dmp ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\SysWOW64\com\dmp:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000020" Name="Block OpsMgrTrace ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Logs\OpsMgrTrace:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000022" Name="Block Servicing Packages ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\servicing\Packages:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000024" Name="Block Temp ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Temp:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000026" Name="Block Temp ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Temp:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000028" Name="Block FxsTmp ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\FxsTmp:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000030" Name="Block System32 Tasks ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\Tasks:*" />
      </Conditions>
    </FilePathRule>
     <FilePathRule Id="00000000-0000-0000-0000-000000000032" Name="Block System32 com dmp ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\com\dmp:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000034" Name="Block DriverData ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\Drivers\DriverData:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000036" Name="Block Printers ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\spool\PRINTERS:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000038" Name="Block Servers ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\spool\SERVERS:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000040" Name="Block Color Drivers ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\spool\drivers\color:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000042" Name="Block SyncCenter ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\Tasks\Microsoft\Windows\SyncCenter:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000044" Name="Block SysWOW64 SyncCenter ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\SysWOW64\Tasks\Microsoft\Windows\SyncCenter:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000046" Name="Block SysWOW64 PLA System ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\SysWOW64\Tasks\Microsoft\Windows\PLA\System:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000048" Name="Block C logs ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="C:\logs:*" />
      </Conditions>
    </FilePathRule>
     <FilePathRule Id="00000000-0000-0000-0000-000000000050" Name="Block User Downloads ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%USERPROFILE%\Downloads:*" />
      </Conditions>
    </FilePathRule>
     <FilePathRule Id="00000000-0000-0000-0000-000000000052" Name="Block AppLocker ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\AppLocker:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000054" Name="Block WIA debug ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\debug\WIA:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000056" Name="Block Event Logs ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\winevt\Logs:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000058" Name="Block CCM Logs ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\ccm\logs:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000060" Name="Block AppVTempData ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\ccm\systemtemp\appvtempdata\appvcommandoutput:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000062" Name="Block NoIDMIFs ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\ccm\inventory\noidmifs:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000066" Name="Block Catroot2 ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\catroot2\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000068" Name="Mitigating VSTO Add-ins Risks 1 ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%LOCALAPPDATA%\Apps\2.0:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000070" Name="Mitigating VSTO Add-ins Risks 2 ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%USERPROFILE%\AppData\Local\assembly:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000072" Name="Mitigating VSTO Add-ins Risks 3 ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%USERPROFILE%\AppData\Local\Apps\2.0:*" />
      </Conditions>
    </FilePathRule>
"@ },
@{ Type = 'Msi'; Xml = @" 
    <FilePathRule Id="00000000-0000-0000-0000-000000000002" Name="Block Tasks ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Tasks:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000004" Name="Block Tracing ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Tracing:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000006" Name="Block Servicing Sessions ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\servicing\Sessions:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000008" Name="Block CRMLog ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Registration\CRMLog:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000010" Name="Block Dlna DeviceIcon ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\ServiceProfiles\LocalService\AppData\Local\Microsoft\Dlna\DeviceIcon:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000012" Name="Block MachineKeys ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\Microsoft\Crypto\RSA\MachineKeys:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000014" Name="Block SysWOW64 FxsTmp ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\SysWOW64\FxsTmp:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000016" Name="Block SysWOW64 Tasks ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\SysWOW64\Tasks:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000018" Name="Block SysWOW64 com dmp ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\SysWOW64\com\dmp:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000020" Name="Block OpsMgrTrace ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Logs\OpsMgrTrace:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000022" Name="Block Servicing Packages ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\servicing\Packages:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000024" Name="Block Temp ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Temp:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000026" Name="Block Temp ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Temp:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000028" Name="Block FxsTmp ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\FxsTmp:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000030" Name="Block System32 Tasks ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\Tasks:*" />
      </Conditions>
    </FilePathRule>
     <FilePathRule Id="00000000-0000-0000-0000-000000000032" Name="Block System32 com dmp ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\com\dmp:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000034" Name="Block DriverData ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\Drivers\DriverData:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000036" Name="Block Printers ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\spool\PRINTERS:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000038" Name="Block Servers ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\spool\SERVERS:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000040" Name="Block Color Drivers ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\spool\drivers\color:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000042" Name="Block SyncCenter ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\Tasks\Microsoft\Windows\SyncCenter:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000044" Name="Block SysWOW64 SyncCenter ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\SysWOW64\Tasks\Microsoft\Windows\SyncCenter:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000046" Name="Block SysWOW64 PLA System ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\SysWOW64\Tasks\Microsoft\Windows\PLA\System:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000048" Name="Block C logs ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="C:\logs:*" />
      </Conditions>
    </FilePathRule>
     <FilePathRule Id="00000000-0000-0000-0000-000000000050" Name="Block User Downloads ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%USERPROFILE%\Downloads:*" />
      </Conditions>
    </FilePathRule>
     <FilePathRule Id="00000000-0000-0000-0000-000000000052" Name="Block AppLocker ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\AppLocker:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000054" Name="Block WIA debug ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\debug\WIA:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000056" Name="Block Event Logs ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\winevt\Logs:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000058" Name="Block CCM Logs ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\ccm\logs:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000060" Name="Block AppVTempData ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\ccm\systemtemp\appvtempdata\appvcommandoutput:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000062" Name="Block NoIDMIFs ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\ccm\inventory\noidmifs:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000066" Name="Block Catroot2 ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\catroot2\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000068" Name="Mitigating VSTO Add-ins Risks 1 ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%LOCALAPPDATA%\Apps\2.0:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000070" Name="Mitigating VSTO Add-ins Risks 2 ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%USERPROFILE%\AppData\Local\assembly:*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000072" Name="Mitigating VSTO Add-ins Risks 3 ads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%USERPROFILE%\AppData\Local\Apps\2.0:*" />
      </Conditions>
    </FilePathRule>
"@ });



    'Rule3' = @(
@{ Type = 'Exe'; Xml = @"
    <FilePathRule Id="00000000-0000-0000-0000-000000000047" Name="Block C logs" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="C:\logs\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000049" Name="Block User Downloads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%USERPROFILE%\Downloads\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000051" Name="Block AppLocker" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\AppLocker\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000067" Name="Mitigating VSTO Add-ins Risks 1" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%LOCALAPPDATA%\Apps\2.0\" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000069" Name="Mitigating VSTO Add-ins Risks 2" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%USERPROFILE%\AppData\Local\assembly\" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000071" Name="Mitigating VSTO Add-ins Risks 3" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%USERPROFILE%\AppData\Local\Apps\2.0\" />
      </Conditions>
    </FilePathRule>
"@ },
@{ Type = 'Script'; Xml = @" 
    <FilePathRule Id="00000000-0000-0000-0000-000000000047" Name="Block C logs" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="C:\logs\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000049" Name="Block User Downloads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%USERPROFILE%\Downloads\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000051" Name="Block AppLocker" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\AppLocker\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000067" Name="Mitigating VSTO Add-ins Risks 1" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%LOCALAPPDATA%\Apps\2.0\" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000069" Name="Mitigating VSTO Add-ins Risks 2" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%USERPROFILE%\AppData\Local\assembly\" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000071" Name="Mitigating VSTO Add-ins Risks 3" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%USERPROFILE%\AppData\Local\Apps\2.0\" />
      </Conditions>
    </FilePathRule>
"@ },
@{ Type = 'Appx'; Xml = @" 
    <FilePathRule Id="00000000-0000-0000-0000-000000000047" Name="Block C logs" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="C:\logs\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000049" Name="Block User Downloads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%USERPROFILE%\Downloads\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000051" Name="Block AppLocker" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\AppLocker\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000067" Name="Mitigating VSTO Add-ins Risks 1" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%LOCALAPPDATA%\Apps\2.0\" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000069" Name="Mitigating VSTO Add-ins Risks 2" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%USERPROFILE%\AppData\Local\assembly\" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000071" Name="Mitigating VSTO Add-ins Risks 3" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%USERPROFILE%\AppData\Local\Apps\2.0\" />
      </Conditions>
    </FilePathRule>
"@ },
@{ Type = 'Msi'; Xml = @" 
    <FilePathRule Id="00000000-0000-0000-0000-000000000047" Name="Block C logs" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="C:\logs\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000049" Name="Block User Downloads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%USERPROFILE%\Downloads\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000051" Name="Block AppLocker" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\AppLocker\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000067" Name="Mitigating VSTO Add-ins Risks 1" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%LOCALAPPDATA%\Apps\2.0\" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000069" Name="Mitigating VSTO Add-ins Risks 2" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%USERPROFILE%\AppData\Local\assembly\" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000071" Name="Mitigating VSTO Add-ins Risks 3" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%USERPROFILE%\AppData\Local\Apps\2.0\" />
      </Conditions>
    </FilePathRule>
"@ },
@{ Type = 'Dll'; Xml = @" 
    <FilePathRule Id="00000000-0000-0000-0000-000000000047" Name="Block C logs" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="C:\logs\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000049" Name="Block User Downloads" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%USERPROFILE%\Downloads\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000051" Name="Block AppLocker" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\AppLocker\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000067" Name="Mitigating VSTO Add-ins Risks 1" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%LOCALAPPDATA%\Apps\2.0\" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000069" Name="Mitigating VSTO Add-ins Risks 2" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%USERPROFILE%\AppData\Local\assembly\" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000071" Name="Mitigating VSTO Add-ins Risks 3" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%USERPROFILE%\AppData\Local\Apps\2.0\" />
      </Conditions>
    </FilePathRule>
"@ }  );

    'Rule4' = @(
@{ Type = 'Exe'; Xml = @"
    <FilePathRule Id="00000000-0000-0000-0000-000000000063" Name="Block bash.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\bash.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000064" Name="Block runscripthelper.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\runscripthelper.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000073" Name="Block addinprocess.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\addinprocess.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000074" Name="Block addinprocess32.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\addinprocess32.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000075" Name="Block addinutil.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\addinutil.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000076" Name="Block aspnet_compiler.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\aspnet_compiler.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000077" Name="Block AtBroker.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\AtBroker.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000078" Name="Block bash.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\bash.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000079" Name="Block bginfo.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\bginfo.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000080" Name="Block cdb.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\cdb.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000081" Name="Block cmstp.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\cmstp.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000082" Name="Block control.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\control.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000083" Name="Block cscript.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\cscript.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000084" Name="Block csi.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\csi.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000085" Name="Block dbghost.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\dbghost.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000086" Name="Block dbgsvc.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\dbgsvc.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000087" Name="Block dbgsrv.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\dbgsrv.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000088" Name="Block dfsvc.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\dfsvc.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000089" Name="Block dnx.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\dnx.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000090" Name="Block dotnet.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\dotnet.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000091" Name="Block forfiles.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\forfiles.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000092" Name="Block fsi.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\fsi.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000093" Name="Block fsiAnyCpu.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\fsiAnyCpu.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000094" Name="Block ie4unit.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\ie4unit.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000095" Name="Block ieexec.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\ieexec.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000096" Name="Block infdefaultinstall.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\infdefaultinstall.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000097" Name="Block kd.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\kd.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000098" Name="Block kill.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\kill.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000099" Name="Block lxrun.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\lxrun.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000100" Name="Block mavinject.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\mavinject.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000101" Name="Block manage-bde.wsf" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\manage-bde.wsf" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000102" Name="Block Microsoft.Workflow.Compiler.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\Microsoft.Workflow.Compiler.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000103" Name="Block msbuild.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\msbuild.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000104" Name="Block msdeploy.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\msdeploy.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000105" Name="Block msdt.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\msdt.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000106" Name="Block mshta.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\mshta.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000107" Name="Block msiexec.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\msiexec.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000108" Name="Block msxsl.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\msxsl.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000109" Name="Block ntkd.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\ntkd.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000110" Name="Block ntsd.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\ntsd.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000111" Name="Block odbcconf.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\odbcconf.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000112" Name="Block powershellcustomhost.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\powershellcustomhost.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000113" Name="Block rcsi.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\rcsi.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000114" Name="Block regsvr32.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\regsvr32.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000115" Name="Block rsi.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\rsi.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000116" Name="Block rundll32.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\rundll32.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000117" Name="Block runscripthelper.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\runscripthelper.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000118" Name="Block syncappvpublishingserver.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\syncappvpublishingserver.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000119" Name="Block te.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\te.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000120" Name="Block texttransform.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\texttransform.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000121" Name="Block tracker.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\tracker.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000122" Name="Block visualuiaverifynative.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\visualuiaverifynative.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000123" Name="Block wfc.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\wfc.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000124" Name="Block windbg.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\windbg.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000125" Name="Block winword.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\winword.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000126" Name="Block wmic.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\wmic.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000127" Name="Block wscript.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\wscript.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000128" Name="Block wsl.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\wsl.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000129" Name="Block wslconfig.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\wslconfig.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000130" Name="Block wslhost.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions> 
        <FilePathCondition Path="%WINDIR%\*\wslhost.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000131" Name="Block xwizard.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\xwizard.exe" />
      </Conditions>
    </FilePathRule>
    <FilePublisherRule Id="00000000-0000-0000-0000-000000000132" Name="Block MSHTA.EXE (.NET utilities)" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="INTERNET EXPLORER" BinaryName="MSHTA.EXE">
          <BinaryVersionRange LowSection="*" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePublisherRule Id="00000000-0000-0000-0000-000000000133" Name="Block MSDT.EXE (Troubleshooting Packs)" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="MICROSOFT® WINDOWS® OPERATING SYSTEM" BinaryName="MSDT.EXE">
          <BinaryVersionRange LowSection="*" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePublisherRule Id="00000000-0000-0000-0000-000000000134" Name="Block KD.EXE  (Debuggers)" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="MICROSOFT® WINDOWS® OPERATING SYSTEM" BinaryName="KD.EXE">
          <BinaryVersionRange LowSection="*" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePublisherRule Id="00000000-0000-0000-0000-000000000135" Name="Block NTSD.EXE  (Debuggers)" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="MICROSOFT® WINDOWS® OPERATING SYSTEM" BinaryName="NTSD.EXE">
          <BinaryVersionRange LowSection="*" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePublisherRule Id="00000000-0000-0000-0000-000000000136" Name="Block BGINFO.EXE (Version 4.22 and below)" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="BGINFO" BinaryName="BGINFO.EXE">
          <BinaryVersionRange LowSection="*" HighSection="4.22.0.0" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePublisherRule Id="00000000-0000-0000-0000-000000000137" Name="Block PRESENTATIONHOST.EXE (WPF Utilities)" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="Microsoft® .NET Framework" BinaryName="PRESENTATIONHOST.EXE">
          <BinaryVersionRange LowSection="*" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePublisherRule Id="00000000-0000-0000-0000-000000000138" Name="Block MSXSL.EXE (COMMAND LINE XSLT)" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="COMMAND LINE XSLT" BinaryName="MSXSL.EXE">
          <BinaryVersionRange LowSection="*" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePublisherRule Id="00000000-0000-0000-0000-000000000139" Name="Block CMSTP.EXE (CONNECTION MANAGER)" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="MICROSOFT(R) CONNECTION MANAGER" BinaryName="CMSTP.EXE">
          <BinaryVersionRange LowSection="*" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePublisherRule Id="00000000-0000-0000-0000-000000000140" Name="Block ODBCCONF.EXE (MDAC Utility)" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="MICROSOFT® WINDOWS® OPERATING SYSTEM" BinaryName="ODBCCONF.EXE">
          <BinaryVersionRange LowSection="*" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePublisherRule Id="00000000-0000-0000-0000-000000000141" Name="Block SYNCAPPVPUBLISHINGSERVER.EXE" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="MICROSOFT (R) WINDOWS (R) OPERATING SYSTEM" BinaryName="SYNCAPPVPUBLISHINGSERVER.EXE">
          <BinaryVersionRange LowSection="*" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePublisherRule Id="00000000-0000-0000-0000-000000000142" Name="Block FSI.EXE (SDK Utility)" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="MICROSOFT® F#" BinaryName="FSI.EXE">
          <BinaryVersionRange LowSection="*" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>  
    <FilePublisherRule Id="00000000-0000-0000-0000-000000000143" Name="Block MAVINJECT32.EXE (APPLICATION VIRTUALIZATION)" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="MICROSOFT APPLICATION VIRTUALIZATION (APP-V)" BinaryName="MAVINJECT32.EXE">
          <BinaryVersionRange LowSection="*" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePublisherRule Id="00000000-0000-0000-0000-000000000144" Name="Block FORFILES.EXE (WINDOWS)" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="MICROSOFT® WINDOWS® OPERATING SYSTEM" BinaryName="FORFILES.EXE">
          <BinaryVersionRange LowSection="*" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePublisherRule Id="00000000-0000-0000-0000-000000000145" Name="Block ATBROKER.EXE (WINDOWS)" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="MICROSOFT® WINDOWS® OPERATING SYSTEM" BinaryName="ATBROKER.EXE">
          <BinaryVersionRange LowSection="*" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePublisherRule Id="00000000-0000-0000-0000-000000000146" Name="Block BASH.EXE (WINDOWS)" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="MICROSOFT® WINDOWS® OPERATING SYSTEM" BinaryName="BASH.EXE">
          <BinaryVersionRange LowSection="*" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePublisherRule Id="00000000-0000-0000-0000-000000000147" Name="Block CSI.EXE (.NET Utilities)" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="" BinaryName="CSI.EXE">
          <BinaryVersionRange LowSection="*" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePublisherRule Id="00000000-0000-0000-0000-000000000148" Name="Block DFSVC.EXE (.NET Utilities)" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="MICROSOFT® .NET FRAMEWORK" BinaryName="DFSVC.EXE">
          <BinaryVersionRange LowSection="*" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePublisherRule Id="00000000-0000-0000-0000-000000000149" Name="Block IEEXEC.EXE (.NET Utilities)" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="MICROSOFT® .NET FRAMEWORK" BinaryName="IEEXEC.EXE">
          <BinaryVersionRange LowSection="*" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePublisherRule Id="00000000-0000-0000-0000-000000000150" Name="Block INSTALLUTIL.EXE (.NET Utilities)" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="MICROSOFT® .NET FRAMEWORK" BinaryName="INSTALLUTIL.EXE">
          <BinaryVersionRange LowSection="*" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePublisherRule Id="00000000-0000-0000-0000-000000000151" Name="Block MSBUILD.EXE (.NET Utilities)" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="MICROSOFT® .NET FRAMEWORK" BinaryName="MSBUILD.EXE">
          <BinaryVersionRange LowSection="*" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePublisherRule Id="00000000-0000-0000-0000-000000000152" Name="Block REGASM.EXE (.NET Utilities)" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="MICROSOFT® .NET FRAMEWORK" BinaryName="REGASM.EXE">
          <BinaryVersionRange LowSection="*" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePublisherRule Id="00000000-0000-0000-0000-000000000153" Name="Block REGSVCS.EXE (.NET Utilities)" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="MICROSOFT® .NET FRAMEWORK" BinaryName="REGSVCS.EXE">
          <BinaryVersionRange LowSection="*" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePublisherRule Id="00000000-0000-0000-0000-000000000154" Name="Block FSIANYCPU.EXE (SDK Utility)" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="MICROSOFT® F#" BinaryName="FSIANYCPU.EXE">
          <BinaryVersionRange LowSection="*" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePublisherRule Id="00000000-0000-0000-0000-000000000155" Name="Block WMIC.EXE (WMI)" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="MICROSOFT® WINDOWS® OPERATING SYSTEM" BinaryName="WMIC.EXE">
          <BinaryVersionRange LowSection="*" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePublisherRule Id="00000000-0000-0000-0000-000000000156" Name="ODBCCONF.EXE, i MICROSOFT® WINDOWS® OPERATING SYSTEM, fra O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
        <Conditions>
          <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="MICROSOFT® WINDOWS® OPERATING SYSTEM" BinaryName="ODBCCONF.EXE">
            <BinaryVersionRange LowSection="*" HighSection="*" />
          </FilePublisherCondition>
        </Conditions>
      </FilePublisherRule>
      <FilePublisherRule Id="00000000-0000-0000-0000-000000000157" Name="CDB.EXE, i MICROSOFT® WINDOWS® OPERATING SYSTEM, fra O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
        <Conditions>
          <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="MICROSOFT® WINDOWS® OPERATING SYSTEM" BinaryName="CDB.EXE">
            <BinaryVersionRange LowSection="*" HighSection="*" />
          </FilePublisherCondition>
        </Conditions>
      </FilePublisherRule>
      <FilePublisherRule Id="00000000-0000-0000-0000-000000000158" Name="RUNDLL32.EXE, i MICROSOFT® WINDOWS® OPERATING SYSTEM, fra O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
        <Conditions>
          <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="MICROSOFT® WINDOWS® OPERATING SYSTEM" BinaryName="RUNDLL32.EXE">
            <BinaryVersionRange LowSection="*" HighSection="*" />
          </FilePublisherCondition>
        </Conditions>
      </FilePublisherRule>
      <FilePublisherRule Id="00000000-0000-0000-0000-000000000159" Name="MAVINJECT64.EXE, i MICROSOFT® WINDOWS® OPERATING SYSTEM, fra O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
        <Conditions>
          <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="MICROSOFT® WINDOWS® OPERATING SYSTEM" BinaryName="MAVINJECT64.EXE">
            <BinaryVersionRange LowSection="*" HighSection="*" />
          </FilePublisherCondition>
        </Conditions>
      </FilePublisherRule>
      <FilePublisherRule Id="00000000-0000-0000-0000-000000000160" Name="WINDBG.EXE, i MICROSOFT® WINDOWS® OPERATING SYSTEM, fra O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
        <Conditions>
          <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="MICROSOFT® WINDOWS® OPERATING SYSTEM" BinaryName="WINDBG.EXE">
            <BinaryVersionRange LowSection="*" HighSection="*" />
          </FilePublisherCondition>
        </Conditions>
      </FilePublisherRule>
      <FilePublisherRule Id="00000000-0000-0000-0000-000000000161" Name="TRACKER.EXE, in MICROSOFT® BUILD TOOLS®, from O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
        <Conditions>
          <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="MICROSOFT® BUILD TOOLS®" BinaryName="TRACKER.EXE">
            <BinaryVersionRange LowSection="*" HighSection="*" />
          </FilePublisherCondition>
        </Conditions>
      </FilePublisherRule>
      <FilePublisherRule Id="00000000-0000-0000-0000-000000000162" Name="INFDEFAULTINSTALL.EXE, in MICROSOFT® WINDOWS® OPERATING SYSTEM, from O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
        <Conditions>
          <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="MICROSOFT® WINDOWS® OPERATING SYSTEM" BinaryName="INFDEFAULTINSTALL.EXE">
            <BinaryVersionRange LowSection="*" HighSection="*" />
          </FilePublisherCondition>
        </Conditions>
      </FilePublisherRule>
      <FilePublisherRule Id="00000000-0000-0000-0000-000000000163" Name="ADDINPROCESS32.EXE, i MICROSOFT® .NET FRAMEWORK, fra O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
        <Conditions>
          <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="MICROSOFT® .NET FRAMEWORK" BinaryName="ADDINPROCESS32.EXE">
            <BinaryVersionRange LowSection="*" HighSection="*" />
          </FilePublisherCondition>
        </Conditions>
      </FilePublisherRule>
      <FilePublisherRule Id="00000000-0000-0000-0000-000000000164" Name="XWIZARD.EXE, i MICROSOFT® WINDOWS® OPERATING SYSTEM, fra O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
        <Conditions>
          <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="MICROSOFT® WINDOWS® OPERATING SYSTEM" BinaryName="XWIZARD.EXE">
            <BinaryVersionRange LowSection="*" HighSection="*" />
          </FilePublisherCondition>
        </Conditions>
      </FilePublisherRule>
      <FilePublisherRule Id="00000000-0000-0000-0000-000000000165" Name="ADDINPROCESS.EXE, i MICROSOFT® .NET FRAMEWORK, fra O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
        <Conditions>
          <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="MICROSOFT® .NET FRAMEWORK" BinaryName="ADDINPROCESS.EXE">
            <BinaryVersionRange LowSection="*" HighSection="*" />
          </FilePublisherCondition>
        </Conditions>
      </FilePublisherRule>
      <FilePublisherRule Id="00000000-0000-0000-0000-000000000166" Name="DBGSVC.EXE, in DEBUG DIAGNOSTIC TOOL, from O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
        <Conditions>
          <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="DEBUG DIAGNOSTIC TOOL" BinaryName="DBGSVC.EXE">
            <BinaryVersionRange LowSection="*" HighSection="*" />
          </FilePublisherCondition>
        </Conditions>
      </FilePublisherRule>
      <FilePublisherRule Id="00000000-0000-0000-0000-000000000167" Name="DBGHOST.EXE, in DEBUG DIAGNOSTIC TOOL, from O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
        <Conditions>
          <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="DEBUG DIAGNOSTIC TOOL" BinaryName="DBGHOST.EXE">
            <BinaryVersionRange LowSection="*" HighSection="*" />
          </FilePublisherCondition>
        </Conditions>
      </FilePublisherRule>
      <FilePublisherRule Id="00000000-0000-0000-0000-000000000168" Name="MAVINJECT32.EXE, i MICROSOFT® WINDOWS® OPERATING SYSTEM, fra O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
        <Conditions>
          <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="MICROSOFT® WINDOWS® OPERATING SYSTEM" BinaryName="MAVINJECT32.EXE">
            <BinaryVersionRange LowSection="*" HighSection="*" />
          </FilePublisherCondition>
        </Conditions>
      </FilePublisherRule>
      <FilePublisherRule Id="00000000-0000-0000-0000-000000000169" Name="REGSVR32.EXE, i MICROSOFT® WINDOWS® OPERATING SYSTEM, fra O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
        <Conditions>
          <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="MICROSOFT® WINDOWS® OPERATING SYSTEM" BinaryName="REGSVR32.EXE">
            <BinaryVersionRange LowSection="*" HighSection="*" />
          </FilePublisherCondition>
        </Conditions>
      </FilePublisherRule>
      <FilePublisherRule Id="00000000-0000-0000-0000-000000000170" Name="ADDINUTIL.EXE, i MICROSOFT® .NET FRAMEWORK, fra O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
        <Conditions>
          <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="MICROSOFT® .NET FRAMEWORK" BinaryName="ADDINUTIL.EXE">
            <BinaryVersionRange LowSection="*" HighSection="*" />
          </FilePublisherCondition>
        </Conditions>
      </FilePublisherRule>
      <FilePublisherRule Id="00000000-0000-0000-0000-000000000171" Name="NTKD.EXE, i MICROSOFT® WINDOWS® OPERATING SYSTEM, fra O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
        <Conditions>
          <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="MICROSOFT® WINDOWS® OPERATING SYSTEM" BinaryName="NTKD.EXE">
            <BinaryVersionRange LowSection="*" HighSection="*" />
          </FilePublisherCondition>
        </Conditions>
      </FilePublisherRule>
"@ });

    'Rule5' = @(
@{ Type = 'Exe'; Xml = @"
    <FilePathRule Id="00000000-0000-0000-0000-000000000242" Name="Block pubprn.vbs" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\pubprn.vbs" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000243" Name="Block slmgr.vbs" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\slmgr.vbs" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000244" Name="Block winrm.vbs" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\winrm.vbs" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000250" Name="CL_Invocation.ps1" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="C:\Windows\diagnostics\system\AERO\CL_Invocation.ps1" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000251" Name="(Default Rule) All scripts located in the Windows folder" Description="Allows members of the Everyone group to run scripts that are located in the Windows folder." UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000252" Name="CL_LoadAssembly.ps1" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="C:\Windows\diagnostics\system\Audio\CL_LoadAssembly.ps1" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000253" Name="Proxy execution with CL_Mutexverifiers.ps1" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="C:\Windows\diagnostics\system\AERO\CL_Mutexverifiers.ps1" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000255" Name="UtilityFunctions.ps1" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="C:\Windows\diagnostics\system\Networking\UtilityFunctions.ps1" />
      </Conditions>
    </FilePathRule>
    <FilePublisherRule Id="00000000-0000-0000-0000-000000000257" Name="Proxy execution with Pubprn.vbs" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="" BinaryName="">
          <BinaryVersionRange LowSection="0.0.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePublisherRule Id="00000000-0000-0000-0000-000000000258" Name="slmgr.vbs" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="" BinaryName="">
          <BinaryVersionRange LowSection="0.0.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePublisherRule Id="00000000-0000-0000-0000-000000000259" Name="winrm.vbs SysWOW64" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="" BinaryName="">
          <BinaryVersionRange LowSection="0.0.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePublisherRule Id="00000000-0000-0000-0000-000000000260" Name="winrm.vbs" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="" BinaryName="">
          <BinaryVersionRange LowSection="0.0.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePublisherRule Id="00000000-0000-0000-0000-000000000261" Name="Pubprn.vbs" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="" BinaryName="">
          <BinaryVersionRange LowSection="0.0.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePublisherRule Id="00000000-0000-0000-0000-000000000262" Name="autorisation pour les scripts signés ps1" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="" BinaryName="">
          <BinaryVersionRange LowSection="0.0.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePublisherRule Id="00000000-0000-0000-0000-000000000263" Name="slmgr.vbs SysWOW64" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="" BinaryName="">
          <BinaryVersionRange LowSection="0.0.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
"@ },
@{ Type = 'Script'; Xml = @" 
    <FilePathRule Id="00000000-0000-0000-0000-000000000242" Name="Block pubprn.vbs" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\pubprn.vbs" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000243" Name="Block slmgr.vbs" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\slmgr.vbs" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000244" Name="Block winrm.vbs" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\winrm.vbs" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000250" Name="CL_Invocation.ps1" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="C:\Windows\diagnostics\system\AERO\CL_Invocation.ps1" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000251" Name="(Default Rule) All scripts located in the Windows folder" Description="Allows members of the Everyone group to run scripts that are located in the Windows folder." UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000252" Name="CL_LoadAssembly.ps1" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="C:\Windows\diagnostics\system\Audio\CL_LoadAssembly.ps1" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000253" Name="Proxy execution with CL_Mutexverifiers.ps1" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="C:\Windows\diagnostics\system\AERO\CL_Mutexverifiers.ps1" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000255" Name="UtilityFunctions.ps1" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="C:\Windows\diagnostics\system\Networking\UtilityFunctions.ps1" />
      </Conditions>
    </FilePathRule>
    <FilePublisherRule Id="00000000-0000-0000-0000-000000000257" Name="Proxy execution with Pubprn.vbs" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="" BinaryName="">
          <BinaryVersionRange LowSection="0.0.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePublisherRule Id="00000000-0000-0000-0000-000000000258" Name="slmgr.vbs" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="" BinaryName="">
          <BinaryVersionRange LowSection="0.0.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePublisherRule Id="00000000-0000-0000-0000-000000000259" Name="winrm.vbs SysWOW64" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="" BinaryName="">
          <BinaryVersionRange LowSection="0.0.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePublisherRule Id="00000000-0000-0000-0000-000000000260" Name="winrm.vbs" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="" BinaryName="">
          <BinaryVersionRange LowSection="0.0.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePublisherRule Id="00000000-0000-0000-0000-000000000261" Name="Pubprn.vbs" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="" BinaryName="">
          <BinaryVersionRange LowSection="0.0.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePublisherRule Id="00000000-0000-0000-0000-000000000262" Name="autorisation pour les scripts signés ps1" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="" BinaryName="">
          <BinaryVersionRange LowSection="0.0.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePublisherRule Id="00000000-0000-0000-0000-000000000263" Name="slmgr.vbs SysWOW64" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="" BinaryName="">
          <BinaryVersionRange LowSection="0.0.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
"@ }    );

'Rule6' = @(
@{ Type = 'Dll'; Xml = @" 
    <FilePathRule Id="00000000-0000-0000-0000-000000000476" Name="Block lxssmanager.dll" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\lxssmanager.dll" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000477" Name="Block Microsoft.Build.dll" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\Microsoft.Build.dll" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000478" Name="Block msbuild.dll" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\msbuild.dll" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000479" Name="Block system.management.automation.dll" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\system.management.automation.dll" />
      </Conditions>
    </FilePathRule>
    <FilePublisherRule Id="00000000-0000-0000-0000-000000000488" Name="ADVPACK.DLL" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="INTERNET EXPLORER" BinaryName="ADVPACK.DLL">
          <BinaryVersionRange LowSection="11.0.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePublisherRule Id="00000000-0000-0000-0000-000000000489" Name="URL.DLL" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="INTERNET EXPLORER" BinaryName="URL.DLL">
          <BinaryVersionRange LowSection="11.0.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePublisherRule Id="00000000-0000-0000-0000-000000000490" Name="ADVPACK.DLL, version 11.0.0.0 and above, in INTERNET EXPLORER" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="INTERNET EXPLORER" BinaryName="ADVPACK.DLL">
          <BinaryVersionRange LowSection="11.0.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePublisherRule Id="00000000-0000-0000-0000-000000000491" Name="ADVPACK.DLL, version 11.0.0.0 and above, in INTERNET EXPLORER" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="INTERNET EXPLORER" BinaryName="ADVPACK.DLL">
          <BinaryVersionRange LowSection="11.0.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePublisherRule Id="00000000-0000-0000-0000-000000000492" Name="url.dll" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="INTERNET EXPLORER" BinaryName="URL.DLL">
          <BinaryVersionRange LowSection="11.0.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePublisherRule Id="00000000-0000-0000-0000-000000000493" Name="ZIPFLDR.DLL" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="MICROSOFT® WINDOWS® OPERATING SYSTEM" BinaryName="ZIPFLDR.DLL">
          <BinaryVersionRange LowSection="10.0.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePublisherRule Id="00000000-0000-0000-0000-000000000494" Name="advpack.dll" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="INTERNET EXPLORER" BinaryName="ADVPACK.DLL">
          <BinaryVersionRange LowSection="11.0.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePublisherRule Id="00000000-0000-0000-0000-000000000495" Name="SHDOCVW.DLL" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="MICROSOFT® WINDOWS® OPERATING SYSTEM" BinaryName="SHDOCVW.DLL">
          <BinaryVersionRange LowSection="10.0.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePublisherRule Id="00000000-0000-0000-0000-000000000496" Name="IEFRAME.DLL" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="INTERNET EXPLORER" BinaryName="IEFRAME.DLL">
          <BinaryVersionRange LowSection="11.0.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePublisherRule Id="00000000-0000-0000-0000-000000000497" Name="ZIPFLDR.DLL, version 10.0.0.0 and above" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="MICROSOFT® WINDOWS® OPERATING SYSTEM" BinaryName="ZIPFLDR.DLL">
          <BinaryVersionRange LowSection="10.0.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePublisherRule Id="00000000-0000-0000-0000-000000000498" Name="IEFRAME.DLL, version 11.0.0.0 and above" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="INTERNET EXPLORER" BinaryName="IEFRAME.DLL">
          <BinaryVersionRange LowSection="11.0.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePublisherRule Id="00000000-0000-0000-0000-000000000499" Name="shdocvw.dll" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="MICROSOFT® WINDOWS® OPERATING SYSTEM" BinaryName="SHDOCVW.DLL">
          <BinaryVersionRange LowSection="10.0.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
"@ });

'Rule7' = @(
@{ Type = 'Script'; Xml = @" 
    <FilePathRule Id="00000000-0000-0000-0000-000000000247" Name="*PEInjection*.ps1" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="*PEInjection*.ps1" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000248" Name="*Reflective*.ps1" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="*Reflective*.ps1" />
      </Conditions>
    </FilePathRule>
    <FileHashRule Id="00000000-0000-0000-0000-000000000256" Name="Invoke-ReflectivePEInjection.ps1" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FileHashCondition>
          <FileHash Type="SHA256" Data="0xF3C0288998194F41986572E0C0CE9724AE29B45165F01887AE825B45A9880CE3" SourceFileName="Invoke-ReflectivePEInjection.ps1" SourceFileLength="151863" />
        </FileHashCondition>
      </Conditions>
    </FileHashRule>
"@ } );

'Rule8' = @(
@{ Type = 'Dll'; Xml = @" 
    <FilePathRule Id="00000000-0000-0000-0000-000000000480" Name="Block .dll in temp" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%TEMP%\*.dll" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000481" Name="Block webclnt.dll" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*\webclnt.dll" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000482" Name="Block .dll in appdata" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%APPDATA%\*.dll" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000483" Name="Block .dll" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="C:\Users\*\AppData\Local\Temp\*.dll" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000484" Name="Block .dll in ProgramData" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="C:\ProgramData\*.dll" />
      </Conditions>
    </FilePathRule>
"@ });

'Rule9' = @(
@{ Type = 'Script'; Xml = @" 
    <FilePathRule Id="00000000-0000-0000-0000-000000000246" Name="Launch-VsDevShell.ps1" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\Tools\Launch-VsDevShell.ps1" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000249" Name="Launch-VsDevShell.ps1 second path" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\Launch-VsDevShell.ps1" />
      </Conditions>
    </FilePathRule>
"@ } );



#     'Rule10' = @"
# <?xml version='1.0' encoding='utf-8'?>
# <AppLockerPolicy Version='1'>
#   <RuleCollection Type='Exe' EnforcementMode='Enabled'>
#     <FilePathRule Id='DefaultAllow' Name='Allow Program Files' Description='Allow program files' UserOrGroupSid='S-1-1-0' Action='Allow'>
#       <Conditions>
#         <FilePathCondition Path='%OSDRIVE%\Program Files*' />
#       </Conditions>
#     </FilePathRule>
#   </RuleCollection>
# </AppLockerPolicy>
# "@


'Rule10' = @(
@{ Type = 'Exe'; Xml = @"
    <FilePathRule
      Id="921cc481-6e17-4653-8f75-050b80acca20"
      Name="(Default Rule) All files located in the Program Files folder"
      Description="Allows members of the Everyone group to run applications that are located in the Program Files folder."
      UserOrGroupSid="S-1-1-0"
      Action="Allow">
      <Conditions>
        <FilePathCondition Path="%PROGRAMFILES%\*" />
      </Conditions>
    </FilePathRule>

    <FilePathRule
      Id="a61c8b2c-a319-4cd0-9690-d2177cad7b51"
      Name="(Default Rule) All files located in the Windows folder"
      Description="Allows members of the Everyone group to run applications that are located in the Windows folder."
      UserOrGroupSid="S-1-1-0"
      Action="Allow">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*" />
      </Conditions>
    </FilePathRule>

    <FilePathRule
      Id="fd686d83-a829-4351-8ff4-27c7de5755d2"
      Name="(Default Rule) All files"
      Description="Allows members of the local Administrators group to run all applications."
      UserOrGroupSid="S-1-5-32-544"
      Action="Allow">
      <Conditions>
        <FilePathCondition Path="*" />
      </Conditions>
    </FilePathRule>
"@ },
@{ Type = 'Script'; Xml = @"
    <FilePathRule
      Id="06dce67b-934c-454f-a263-2515c8796a5d"
      Name="(Default Rule) All scripts located in the Program Files folder"
      Description="Allows members of the Everyone group to run scripts that are located in the Program Files folder."
      UserOrGroupSid="S-1-1-0"
      Action="Allow">
      <Conditions>
        <FilePathCondition Path="%PROGRAMFILES%\*" />
      </Conditions>
    </FilePathRule>

    <FilePathRule
      Id="9428c672-5fc3-47f4-808a-a0011f36dd2c"
      Name="(Default Rule) All scripts located in the Windows folder"
      Description="Allows members of the Everyone group to run scripts that are located in the Windows folder."
      UserOrGroupSid="S-1-1-0"
      Action="Allow">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*" />
      </Conditions>
    </FilePathRule>

    <FilePathRule
      Id="ed97d0cb-15ff-430f-b82c-8d7832957725"
      Name="(Default Rule) All scripts"
      Description="Allows members of the local Administrators group to run all scripts."
      UserOrGroupSid="S-1-5-32-544"
      Action="Allow">
      <Conditions>
        <FilePathCondition Path="*" />
      </Conditions>
    </FilePathRule> 
"@ },
@{ Type = 'Appx'; Xml = @" 
 <FilePublisherRule
      Id="a9e18c21-ff8f-43cf-b9fc-db40eed693ba"
      Name="(Default Rule) All signed packaged apps"
      Description="Allows members of the Everyone group to run packaged apps that are signed."
      UserOrGroupSid="S-1-1-0"
      Action="Allow">
      <Conditions>
        <FilePublisherCondition PublisherName="*" ProductName="*" BinaryName="*">
          <BinaryVersionRange LowSection="0.0.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
 </FilePublisherRule>
"@ },
@{ Type = 'Msi'; Xml = @" 
    <FilePublisherRule
      Id="b7af7102-efde-4369-8a89-7a6a392d1473"
      Name="(Default Rule) All digitally signed Windows Installer files"
      Description="Allows members of the Everyone group to run digitally signed Windows Installer files."
      UserOrGroupSid="S-1-1-0"
      Action="Allow">
      <Conditions>
        <FilePublisherCondition PublisherName="*" ProductName="*" BinaryName="*">
          <BinaryVersionRange LowSection="0.0.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>

    <FilePathRule
      Id="5b290184-345a-4453-b184-45305f6d9a54"
      Name="(Default Rule) All Windows Installer files in %systemdrive%\Windows\Installer"
      Description="Allows members of the Everyone group to run all Windows Installer files located in %systemdrive%\Windows\Installer."
      UserOrGroupSid="S-1-1-0"
      Action="Allow">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Installer\*" />
      </Conditions>
    </FilePathRule>

    <FilePathRule
      Id="64ad46ff-0d71-4fa0-a30b-3f3d30c5433d"
      Name="(Default Rule) All Windows Installer files"
      Description="Allows members of the local Administrators group to run all Windows Installer files."
      UserOrGroupSid="S-1-5-32-544"
      Action="Allow">
      <Conditions>
        <FilePathCondition Path="*.*" />
      </Conditions>
    </FilePathRule>
"@ },
@{ Type = 'Dll'; Xml = @" 
    <FilePathRule
      Id="bac4b0bf-6f1b-40e8-8627-8545fa89c8b6"
      Name="(Default Rule) Microsoft Windows DLLs"
      Description="Allows members of the Everyone group to load DLLs located in the Windows folder."
      UserOrGroupSid="S-1-1-0"
      Action="Allow">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*" />
      </Conditions>
    </FilePathRule>

    <FilePathRule
      Id="3737732c-99b7-41d4-9037-9cddfb0de0d0"
      Name="(Default Rule) All DLLs located in the Program Files folder"
      Description="Allows members of the Everyone group to load DLLs that are located in the Program Files folder."
      UserOrGroupSid="S-1-1-0"
      Action="Allow">
      <Conditions>
        <FilePathCondition Path="%PROGRAMFILES%\*" />
      </Conditions>
    </FilePathRule>

    <FilePathRule
      Id="fe64f59f-6fca-45e5-a731-0f6715327c38"
      Name="(Default Rule) All DLLs"
      Description="Allows members of the local Administrators group to load all DLLs."
      UserOrGroupSid="S-1-5-32-544"
      Action="Allow">
      <Conditions>
        <FilePathCondition Path="*" />
      </Conditions>
    </FilePathRule>
"@ }
         );}


# ===========================================================
# APPLY APPLOCKER RULES
# ===========================================================

# ===========================================================
# APPLY APPLOCKER RULES
# ===========================================================
function Refresh-AppLockerGUI {
    Write-Host "Refreshing AppLocker GUI..." -ForegroundColor Cyan
    Get-Process mmc -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowTitle -like "*Local Security*" } | Stop-Process -Force
    Start-Sleep -Seconds 1
    Start-Process "secpol.msc"
}

function Apply-AppLockerRules {
    param ([array]$SelectedRules)

    Write-SectionHeader "APPLYING POLICY"
    Show-Spinner -Message "Initializing policy build"

    Write-Log "Starting to apply selected rules..."

    
    # Create a temporary XML document to build our final policy
    $fullXmlDoc = New-Object System.Xml.XmlDocument
    $root = $fullXmlDoc.CreateElement("AppLockerPolicy")
    $fullXmlDoc.AppendChild($root) | Out-Null
    $versionAttr = $fullXmlDoc.CreateAttribute("Version")
    $versionAttr.Value = "1"
    $root.Attributes.Append($versionAttr) | Out-Null
    
    # Create collections for each type
    $collectionTypes = @("Exe", "Script", "Msi", "AppX", "Dll")
    $collections = @{}
    
    foreach ($type in $collectionTypes) {
        $collection = $fullXmlDoc.CreateElement("RuleCollection")
        $typeAttr = $fullXmlDoc.CreateAttribute("Type")
        $typeAttr.Value = $type
        $collection.Attributes.Append($typeAttr) | Out-Null
        
        $enforcementAttr = $fullXmlDoc.CreateAttribute("EnforcementMode")

        $enforcementAttr.Value = $EnforcementMode

        $collection.Attributes.Append($enforcementAttr) | Out-Null
        
        $root.AppendChild($collection) | Out-Null
        $collections[$type] = $collection
    }

    
   # Initialize incremental counter for rule IDs
$globalRuleIdCounter = 1

# Process other rules by adding them to our XML document
$ruleCount = 0
foreach ($rule in $SelectedRules) {

    foreach ($entry in $BuiltInRules[$rule.RuleID]) {
        $type = $entry.Type

        $tempDoc = New-Object System.Xml.XmlDocument
        try {
            $tempDoc.LoadXml("<root>" + $entry.Xml + "</root>")
            $ruleNodes = $tempDoc.DocumentElement.ChildNodes

            foreach ($ruleNode in $ruleNodes) {
                # Replace ID with incremental format
                if ($ruleNode.Attributes["Id"]) {
    $ruleNode.Attributes["Id"].Value = "00000000-0000-0000-0000-{0:D12}" -f $globalRuleIdCounter
    $globalRuleIdCounter++
}


                $importedNode = $fullXmlDoc.ImportNode($ruleNode, $true)
                $collections[$type].AppendChild($importedNode) | Out-Null
                $ruleCount++
                # Write-Log "Added rule of type $type with ID: $($ruleNode.Attributes["Id"].Value)"
            }
        } catch {
            Write-Log "Error processing rule XML: $_"
        }
    }
}

    
    # If we have no regular rules (just Rule10), we're done
    if ($ruleCount -eq 0 -and $hasRule10) {
        Write-Host "Applied only default allow policy." -ForegroundColor Green
        return
    }
    
    # If we have no rules at all, exit
    if ($ruleCount -eq 0 -and -not $hasRule10) {
        Write-Host "No rules selected or available to apply." -ForegroundColor Yellow
        return
    }
    Write-SectionHeader "FINALIZING POLICY"
    Show-Spinner -Message "Applying generated policy"
    
    # Save and apply the generated policy
    try {
        $tempFile = [System.IO.Path]::GetTempFileName()
        $fullXmlDoc.Save($tempFile)
        
        # Save a copy for reference
        $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $policyFile = "$policyDir\custom-policy-$timestamp.xml"
        Copy-Item -Path $tempFile -Destination $policyFile
        
        # Apply the policy
        Set-AppLockerPolicy -XmlPolicy $tempFile -Merge
        Remove-Item -Path $tempFile -Force
        
        # Write-Log "Applied $ruleCount custom rules and saved policy to $policyFile"
        Write-Host "Successfully applied $ruleCount custom rules. Policy saved to $policyFile" -ForegroundColor Green
    } catch {
        Write-Log "Error applying custom rules: $_"
        Write-Host "Failed to apply custom rules: $_" -ForegroundColor Red
    }
}

# ===========================================================
# CUSTOM PROFILE MENU
# ===========================================================

function Invoke-CustomProfileMenu {
    $rules = @(
        @{ Name = "Block Execution in Writable System Directories"; RuleID = "Rule1"; Types = @("Exe", "Script","Msi","Appx","Dll") },
        @{ Name = "Prevent Alternate Data Stream (ADS) Exploits"; RuleID = "Rule2"; Types = @("Exe", "Script","Appx","Dll","Msi") },
        @{ Name = "Block Known User-Writable Dangerous Paths"; RuleID = "Rule3"; Types = @("Exe","Script","Appx","Msi","Dll") },
        @{ Name = "Block LOLBAS (.exe )"; RuleID = "Rule4"; Types = @("Exe") },
        @{ Name = "Block LOLBAS (.ps,.vbs )"; RuleID = "Rule5"; Types = @("Exe", "Script") },
        @{ Name = "Block LOLBAS (.dll )"; RuleID = "Rule6"; Types = @("Dll") },
        @{ Name = "Block Reflective PE Injection "; RuleID = "Rule7"; Types = @("Script") },
        @{ Name = "Block DLL hijack paths"; RuleID = "Rule8"; Types = @("Dll") },
        @{ Name = "Block Unsigned PowerShell Scripts"; RuleID = "Rule9"; Types = @("Script") },
        @{ Name = "Allow default rules"; RuleID = "Rule10"; Types = @("Exe","Script","Appx","Msi","Dll") }
    )

    Write-Host "`nSelect rules to apply (comma-separated numbers):"
    for ($i = 0; $i -lt $rules.Count; $i++) {
        Write-Host " $($i+1). $($rules[$i].Name)"
    }

    $selection = Read-Host "`nEnter your choices (e.g. 1,2)"
    $selectedIndexes = $selection -split "," | ForEach-Object { ($_ -as [int]) - 1 }
    $selectedRules = $selectedIndexes | Where-Object { $_ -ge 0 -and $_ -lt $rules.Count } | ForEach-Object { $rules[$_] }
    
    if ($selectedRules.Count -eq 0) {
        Write-Host "No valid rules selected." -ForegroundColor Yellow
        return
    }
    
    # Show selected rules summary
    Write-Host "`nSelected rules to apply:" -ForegroundColor Cyan
    foreach ($rule in $selectedRules) {
        Write-Host " - $($rule.Name)" -ForegroundColor Green
    }
    $modeChoice = Read-Host "Choose mode: [1] AuditOnly (default) or [2] Enforcement"
    switch ($modeChoice) {
        "2" { $global:EnforcementMode = "Enforcement" }
        default { $global:EnforcementMode = "AuditOnly" }
    }
    # Write-Host "Selected mode: $EnforcementMode" -ForegroundColor Cyan

    $confirm = Read-Host "`nApply these rules? (Y/N)"
    if ($confirm -ne "Y" -and $confirm -ne "y") {
        Write-Host "Operation cancelled." -ForegroundColor Yellow
        return
    }
    
    # Write-Host "Applying rules..." -ForegroundColor Cyan
    Set-AppLockerPolicy -XMLPolicy $env:USERPROFILE\Desktop\clear.xml
    Apply-AppLockerRules -SelectedRules $selectedRules
    Refresh-AppLockerGUI

}

# ===========================================================
# PROFILE APPLICATION
# ===========================================================
function Apply-Profile {
   Write-SectionHeader "PROFILE SELECTION"

    # ➤ Add user guidance here
    Write-Host "Choose and apply a predefined AppLocker rule set based on your `n security needs." -ForegroundColor DarkGray
    Write-Host ""

    Write-Host "Select a profile to apply:`n"

    Write-Host "    1. Basic" -ForegroundColor Cyan
    Write-Host "       Light protection for regular users, blocks common attack paths.`n" -ForegroundColor DarkGray

    Write-Host "    2. Hardened (recommended)" -ForegroundColor Cyan
    Write-Host "       Stricter rules that block most known bypasses, ideal for admins.`n" -ForegroundColor DarkGray

    Write-Host "    3. Custom" -ForegroundColor Cyan
    Write-Host "       Manually choose which rules to apply, for advanced users.`n" -ForegroundColor DarkGray

    $profileChoice = Read-Host "Enter your choice"

    
    # Skip enforcement mode selection for custom profiles (handled separately)
    if ($profileChoice -ne "3") {
        Write-Host "`nSelect enforcement mode:"
        Write-Host "    1. Audit Only (logs violations but doesn't block)"
        Write-Host "    2. Enabled (blocks violations)"
        $enforcementChoice = Read-Host "`nEnter enforcement mode"
        
        $enforcementMode = switch ($enforcementChoice) {
            "1" { "AuditOnly" }
            "2" { "Enabled" }
            default { 
                Write-Host "Invalid enforcement mode selection. Using Audit Only as default." -ForegroundColor Yellow
                "AuditOnly" 
            }
        }
        Write-Host "Selected enforcement mode: $enforcementMode" -ForegroundColor Green
    }
    
    $profileDir = "Applocker-Profiles"
    
    # Backup current policy
    $backupPath = "backup\applocker-backup-$((Get-Date).ToString('yyyyMMdd-HHmmss')).xml"
    if (!(Test-Path -Path "backup")) { New-Item -ItemType Directory -Path "backup" | Out-Null }
    try {
        (Get-AppLockerPolicy -Local -Xml) | Out-File -FilePath $backupPath
        Write-Log "Backed up current policy to $backupPath"
    } catch {
        Write-Host " Failed to backup current policy: $_" -ForegroundColor Yellow
    }
    
    switch ($profileChoice) {
        "1" {
            $file = "$profileDir\Basic.xml"
            if (Test-Path $file) {
                Apply-ProfileWithEnforcement -ProfilePath $file -EnforcementMode $enforcementMode -ProfileName "Basic"
            } else {
                Write-Host "Basic profile file not found." -ForegroundColor Red
            }
        }
        "2" {
            $file = "$profileDir\Hardened.xml"
            if (Test-Path $file) {
                Apply-ProfileWithEnforcement -ProfilePath $file -EnforcementMode $enforcementMode -ProfileName "Hardened"
            } else {
                Write-Host "Hardened profile file not found." -ForegroundColor Red
            }
        }
        "3" {
            Invoke-CustomProfileMenu
        }
        default {
            Write-Host "Invalid selection." -ForegroundColor Red
        }
    }
}

function Apply-ProfileWithEnforcement {
    param(
        [string]$ProfilePath,
        [string]$EnforcementMode,
        [string]$ProfileName
    )
    
    try {
        # Read the XML content
        [xml]$xmlContent = Get-Content -Path $ProfilePath
        
        # Update enforcement mode for all rule collections
        $ruleCollections = $xmlContent.AppLockerPolicy.RuleCollection
        foreach ($collection in $ruleCollections) {
            if ($collection) {
                $collection.EnforcementMode = $EnforcementMode
                # Write-Host "Updated $($collection.Type) rules to $EnforcementMode mode" -ForegroundColor Cyan
            }
        }
        
        # Save the modified XML to a temporary file
        $tempPath = "$env:TEMP\temp_applocker_policy.xml"
        $xmlContent.Save($tempPath)
        
        # Apply the policy
        Set-AppLockerPolicy -XMLPolicy $tempPath
        Refresh-AppLockerGUI
        
        # Clean up temporary file
        Remove-Item -Path $tempPath -Force -ErrorAction SilentlyContinue
        
        Write-Host "$ProfileName profile applied with $EnforcementMode enforcement mode." -ForegroundColor Green
        # Write-Log "Applied $ProfileName profile with $EnforcementMode enforcement mode from $ProfilePath"
        
    } catch {
        Write-Host "Failed to apply $ProfileName profile: $_" -ForegroundColor Red
        Write-Log "Error applying $ProfileName profile: $_"
    }
}

# Helper function to display current enforcement status
function Show-EnforcementStatus {
    Write-Host "`nCurrent AppLocker Enforcement Status:" -ForegroundColor Yellow
    try {
        $policy = Get-AppLockerPolicy -Local
        $ruleCollections = $policy.RuleCollections
        
        foreach ($collection in $ruleCollections) {
            $ruleCount = $collection.Rules.Count
            Write-Host "  $($collection.RuleCollectionType): $($collection.EnforcementMode) ($ruleCount rules)" -ForegroundColor Cyan
        }
    } catch {
        Write-Host "  Unable to retrieve current enforcement status" -ForegroundColor Red
    }
}
# ===========================================================
# MENU OPTIONS
# ===========================================================

function Scan-System {
    Write-SectionHeader "SCANNING SYSTEM"
    Write-Host "Analyze the system for common AppLocker misconfigurations and risky paths`n" -ForegroundColor DarkGray
    Show-Spinner -Message "Analyzing AppLocker policies"

    Write-Host "`n[+] Scanning system for AppLocker weaknesses..." -ForegroundColor Green
    $weaknesses = @()

    # Get the current effective AppLocker policy
    try {
        $policy = Get-AppLockerPolicy -Effective -Xml
        $policyObj = [xml]$policy
    } catch {
        $weaknesses += "AppLocker policy not found. No restrictions in place."
        Write-Log "AppLocker policy not found."
        return
    }

    # Helper: Collect all rule patterns (FilePathCondition) by type
    function Get-PathsByType($type) {
        return $policyObj.SelectNodes("//RuleCollection[@Type='$type']/*/Conditions/FilePathCondition") |
            ForEach-Object { $_.Path }
    }
    # Helper: Search deny paths for a pattern
    function IsPathBlocked($pattern, $type) {
        $paths = Get-PathsByType $type
        return $paths -contains $pattern
    }
    # 0. Check enforcement modes
    # foreach ($type in "Exe", "Script", "Dll", "Msi", "Appx") {
    #     $collection = $policyObj.AppLockerPolicy.RuleCollection | Where-Object { $_.Type -eq $type }
    #     if (-not $collection) {
    #         $weaknesses += " No rules for type: $type"
    #         continue
    #     }
    #     if ($collection.EnforcementMode -ne "Enabled") {
    #         $weaknesses += "  $type rules are set to '${collection.EnforcementMode}', not 'Enabled'"
    #     }
    # }

    # === RULE 1: Writable System Paths ===
    $criticalPaths = @(
        "%WINDIR%\Tasks\*", "%WINDIR%\Tracing\*", "%WINDIR%\Temp\*", "%SYSTEM32%\Tasks\*",
        "%SYSTEM32%\Drivers\DriverData\*", "%SYSTEM32%\spool\PRINTERS\*", "%SYSTEM32%\winevt\Logs\*"
    )
    foreach ($p in $criticalPaths) {
        if (-not (IsPathBlocked $p "Exe")) {
            $weaknesses += "Writable system path not blocked: $p"
        }
    }

    # === RULE 2: ADS Exploits ===
    $adsBlocked = $false
    foreach ($node in $policyObj.SelectNodes("//FilePathCondition")) {
        if ($node.Path -like "*:*") {
            $adsBlocked = $true
            break
        }
    }
    if (-not $adsBlocked) {
        $weaknesses += "No rule blocking Alternate Data Streams (ADS)"
    }

    # === RULE 3: Dangerous User Paths ===
    $userPaths = @(
        "%USERPROFILE%\Downloads\*", "%LOCALAPPDATA%\Apps\2.0\*", "%USERPROFILE%\AppData\Local\assembly\*"
    )
    foreach ($p in $userPaths) {
        if (-not (IsPathBlocked $p "Exe")) {
            $weaknesses += "Dangerous writable path not blocked: $p"
        }
    }

    # === RULES 4-6: LOLBins by Path ===
    $lolbins = @("mshta.exe", "regsvr32.exe", "wmic.exe", "rundll32.exe", "msbuild.exe", "InstallUtil.exe", "cmstp.exe", "msdt.exe")
    $exePaths = Get-PathsByType "Exe"
    foreach ($bin in $lolbins) {
        if (-not ($exePaths | Where-Object { $_ -like "*$bin" })) {
            $weaknesses += "LOLBin not blocked: $bin"
        }
    }

    # === RULE 7: Reflective PE Injection ===
    if (-not ($exePaths | Where-Object { $_ -like "*Reflective*" -or $_ -like "*PEInjection*" })) {
        $weaknesses += "No path rule found blocking Reflective PE Injection scripts"
    }

    # === RULE 8: DLL Hijacking Paths ===
    $dllHijackPaths = @("%TEMP%\*.dll", "%APPDATA%\*.dll", "C:\Users\*\AppData\Local\Temp\*.dll", "C:\ProgramData\*.dll")
    foreach ($p in $dllHijackPaths) {
        if (-not (IsPathBlocked $p "Dll")) {
            $weaknesses += "DLL hijack path not blocked: $p"
        }
    }

    # === RULE 9: Unsigned PowerShell Scripts ===
    $scriptPaths = Get-PathsByType "Script"
    if (-not ($scriptPaths | Where-Object { $_ -like "*.ps1" -and $_ -like "*deny*" })) {
        $weaknesses += "No rules blocking unsigned or dangerous PowerShell scripts"
    }

    # === RULE 10: Audit-Only Default Policy Check ===
    $collections = $policyObj.AppLockerPolicy.RuleCollection
    foreach ($c in $collections) {
        if ($c.EnforcementMode -eq "AuditOnly") {
            $weaknesses += " AppLocker type [$($c.Type)] is in AuditOnly mode"
        }
    }

    # === Final Report ===
    if ($weaknesses.Count -eq 0) {
        Write-Host "`n No major AppLocker weaknesses found." -ForegroundColor Green
        Write-Log "System scan completed. No major weaknesses found."
    } else {
        Write-Host "`nDetected AppLocker weaknesses:`n" -ForegroundColor Yellow
        foreach ($issue in $weaknesses) {
            Write-Host " - $issue" -ForegroundColor Red
            # Write-Log $issue
        }
    }
}



function Review-And-Export {
    Write-SectionHeader "EXPORTING CURRENT POLICY"
    Write-Host "Save the current AppLocker policy as an XML backup`n" -ForegroundColor DarkGray
    # Write-Host "[+] Reviewing policy..."
    try {
        $currentPolicy = Get-AppLockerPolicy -Local -Xml
        if ($currentPolicy) {
            $exportPath = "$policyDir\current-policy-$((Get-Date).ToString('yyyyMMdd-HHmmss')).xml"
            $currentPolicy | Out-File -FilePath $exportPath -Encoding utf8
            Write-Host "Current policy exported to $exportPath" -ForegroundColor Green
            Write-Log "Policy exported to $exportPath"
        } else {
            Write-Host "No AppLocker policy found to export" -ForegroundColor Yellow
            Write-Log "No policy found to export"
        }
    } catch {
        Write-Host "Failed to export policy: $_" -ForegroundColor Red
        Write-Log "Failed to export policy: $_"
    }
}

function Rollback-Policy {
    Write-SectionHeader "ROLLBACK POLICY"
    Write-Host "Restore the previously applied AppLocker configuration`n" -ForegroundColor DarkGray
    $backupFiles = Get-ChildItem -Path $backupDir -Filter "*.xml" | Sort-Object LastWriteTime -Descending
    
    if ($backupFiles.Count -eq 0) {
        Write-Host "No backup files found." -ForegroundColor Yellow
        return
    }
    
    Write-Host "`nAvailable backups:"
    for ($i = 0; $i -lt [Math]::Min(5, $backupFiles.Count); $i++) {
        Write-Host " $($i+1). $($backupFiles[$i].Name) - $($backupFiles[$i].LastWriteTime)"
    }
    
    $choice = Read-Host "`nSelect a backup to restore (0 to cancel)"
    
    if ($choice -eq "0") {
        Write-Host "Rollback cancelled." -ForegroundColor Yellow
        return
    }
    
    $index = [int]$choice - 1
    if ($index -ge 0 -and $index -lt $backupFiles.Count) {
        $selectedBackup = $backupFiles[$index].FullName
        try {
            Set-AppLockerPolicy -XmlPolicy $selectedBackup
            Write-Host "Successfully restored policy from $($backupFiles[$index].Name)" -ForegroundColor Green
            Write-Log "Restored policy from $($backupFiles[$index].Name)"
            Refresh-AppLockerGUI
        } catch {
            Write-Host "Failed to restore policy: $_" -ForegroundColor Red
            Write-Log "Failed to restore policy: $_"
        }
    } else {
        Write-Host "Invalid selection." -ForegroundColor Red
    }
}

function View-Report {
    Write-SectionHeader "VIEWING LOGS"
    Write-Host "`nReview changes made by the hardening tool." -ForegroundColor DarkGray
    if (Test-Path -Path $logPath) {
        Write-Host "`n=== AppLocker Hardening Log ===" -ForegroundColor Cyan
        Get-Content -Path $logPath | ForEach-Object {
            Write-Host $_
        }
        Write-Host "=== End of Log ===" -ForegroundColor Cyan
    } else {
        Write-Host "No log file found." -ForegroundColor Yellow
    }
}

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class ConsoleFont {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetCurrentConsoleFontEx(IntPtr hConsoleOutput, bool bMaximumWindow, ref CONSOLE_FONT_INFO_EX lpConsoleCurrentFontEx);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetStdHandle(int nStdHandle);

    private const int STD_OUTPUT_HANDLE = -11;
    private const int LF_FACESIZE = 32;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CONSOLE_FONT_INFO_EX {
        public int cbSize;
        public int nFont;
        public COORD dwFontSize;
        public int FontFamily;
        public int FontWeight;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = LF_FACESIZE)]
        public string FaceName;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct COORD {
        public short X;
        public short Y;
    }

    public static void SetFontSize(short x, short y) {
        IntPtr hnd = GetStdHandle(STD_OUTPUT_HANDLE);
        CONSOLE_FONT_INFO_EX info = new CONSOLE_FONT_INFO_EX();
        info.cbSize = Marshal.SizeOf(info);
        info.FaceName = "Consolas";
        info.dwFontSize = new COORD() { X = x, Y = y };
        info.FontFamily = 0;
        info.FontWeight = 400;
        SetCurrentConsoleFontEx(hnd, false, ref info);
    }
}
"@

# Set font size (e.g., width 10, height 24)
[ConsoleFont]::SetFontSize(10, 24)


# === DARK CONSOLE STYLE ===
$Host.UI.RawUI.BackgroundColor = 'Black'
$Host.UI.RawUI.ForegroundColor = 'White'
Clear-Host

$banner = @'
 _   _               _  _            _             
| | | | __ _ _ __ __| || | ___   ___| | __ __ _ __ 
| |_| |/ _` | '__/ _` || |/ _ \ / __| |/ / _ \ '__|
|  _  | (_| | | | (_| || | (_) | (__|   <  __/ |   
|_| |_|\__,_|_|  \__,_||_|\___/ \___|_|\_\___|_|   

        [ HARDLOCKER :: AppLocker Hardening Tool ]
'@
Write-Host "`n$banner" -ForegroundColor Green
Write-Host "====================== HARDLOCKER - By Hazy ========================================================" -ForegroundColor White


# === SESSION INFO ===
$whoami = "$env:USERNAME@$env:COMPUTERNAME"
$hostip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike "*Loopback*" }).IPAddress | Select-Object -First 1
Write-Host "SESSION: $whoami" -ForegroundColor Gray
Write-Host "IP:      $hostip" -ForegroundColor Gray
Write-Host "====================================================================================================" -ForegroundColor White

while ($true) {
   Write-Host "========================= MAIN MENU ================================================================" -ForegroundColor White
    Write-Host "  1." -NoNewline; Write-Host " Apply Profile (Basic / Hardened / Custom)" -ForegroundColor Green
    Write-Host "  2." -NoNewline; Write-Host " Scan System for Weaknesses" -ForegroundColor Green
    Write-Host "  3." -NoNewline; Write-Host " Export Policy" -ForegroundColor Green
    Write-Host "  4." -NoNewline; Write-Host " Rollback to Previous Policy" -ForegroundColor Green
    Write-Host "  5." -NoNewline; Write-Host " View Logs" -ForegroundColor Green
    Write-Host "  0." -NoNewline; Write-Host " Exit" -ForegroundColor Green
    Write-Host "====================================================================================================" -ForegroundColor White


    $choice = Read-Host "`nSelect an option"

    switch ($choice) {
        "1" { Apply-Profile }
        "2" { Scan-System }
        "3" { Review-And-Export }
        "4" { Rollback-Policy }
        "5" { View-Report }
        "0" { Write-Host "Exiting..."; exit }
        default { Write-Host "Invalid option. Please select a valid number." -ForegroundColor Red }
    }
}

function Write-Status {
    param (
        [string]$Message,
        [ValidateSet("OK", "FAIL", "INFO", "WARN")]
        [string]$Level = "INFO"
    )
    switch ($Level) {
        "OK"   { Write-Host "[+] $Message" -ForegroundColor Green }
        "FAIL" { Write-Host "[-] $Message" -ForegroundColor Red }
        "INFO" { Write-Host "[i] $Message" -ForegroundColor Cyan }
        "WARN" { Write-Host "[!] $Message" -ForegroundColor Yellow }
    }
}
