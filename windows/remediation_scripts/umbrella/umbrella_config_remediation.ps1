[CmdletBinding()]
param ()

# Defines paths for the Umbrella configuration directories, OrgInfo file, VPN CLI, and scheduled task artifacts
$UmbrellaFolder     = "C:\ProgramData\Cisco\Cisco Secure Client\Umbrella"
$UmbrellaDataFolder = "C:\ProgramData\Cisco\Cisco Secure Client\Umbrella\data"
$UmbrellaSWGFolder  = "C:\ProgramData\Cisco\Cisco Secure Client\Umbrella\SWG"
$JSONFileName       = "OrgInfo.json"
$JSONFilePath       = Join-Path -Path $UmbrellaFolder -ChildPath $JSONFileName
$VPNCLIPath         = "C:\Program Files (x86)\Cisco\Cisco Secure Client\vpncli.exe"
$VPNAgentService    = "csc_vpnagent"
$FlagFolder         = "C:\ProgramData\Cisco\CSCEnforcement"
$PromptResponseFile = Join-Path $FlagFolder "prompt_response.txt"
$PromptScriptFile   = Join-Path $FlagFolder "prompt_script.ps1"
$PromptTaskName     = "CSC_OrgInfo_UserPrompt"

# Defines the authoritative OrgInfo JSON content to be written during remediation
$JSONContent = @'
{
    "fingerprint": "abcdef1234567890",
    "organizationId": "0000000",
    "region": "global",
    "userId": "00000000"
}
'@

# Queries vpncli.exe to determine whether a VPN session is currently active
function Get-VPNStatus {
    [CmdletBinding()]
    param ()

    if (Test-Path $VPNCLIPath) {
        try {
            $VPNState = & "$VPNCLIPath" state 2>&1 | Out-String
            if ($VPNState -match "state: Connected") { return $true }
        } catch {
            Write-Verbose "VPN status check failed: $_"
            return $false
        }
    }
    return $false
}

# Issues a disconnect command via vpncli.exe and polls until the session terminates or the timeout elapses
function Disconnect-VPN {
    [CmdletBinding()]
    param ()

    if (Test-Path $VPNCLIPath) {
        try {
            & "$VPNCLIPath" disconnect 2>&1 | Out-Null
        } catch {
            Write-Verbose "VPN disconnect failed: $_"
            return $false
        }
        $Timeout = 15
        $Elapsed = 0
        while ($Elapsed -lt $Timeout) {
            Start-Sleep -Seconds 1
            $Elapsed++
            if (-not (Get-VPNStatus)) { return $true }
        }
    }
    return $false
}

# Resolves the VPN agent service by name, falling back to a display-name pattern match if the primary name is not found
function Get-VPNAgentService {
    [CmdletBinding()]
    param ()

    $Service = $null
    try {
        $Service = Get-Service -Name $VPNAgentService -ErrorAction Stop
    } catch {
        $Service = Get-Service | Where-Object {
            $_.DisplayName -match "Cisco Secure Client Agent" -or
            $_.DisplayName -match "Cisco AnyConnect"
        } | Select-Object -First 1
    }
    return $Service
}

# Attempts a graceful stop of the VPN agent service, escalating to a forced stop and process kill if the timeout elapses
function Stop-VPNAgentService {
    [CmdletBinding()]
    param ()

    $Service = Get-VPNAgentService
    if ($null -eq $Service) { return $false }

    try {
        Stop-Service -Name $Service.Name -ErrorAction Stop
    } catch {
        Write-Verbose "Graceful stop failed: $_"
    }

    $Timeout = 60
    $Elapsed = 0
    while ($Elapsed -lt $Timeout) {
        Start-Sleep -Seconds 2
        $Elapsed += 2
        if ((Get-Service -Name $Service.Name).Status -eq "Stopped") {
            $AgentProcess = Get-Process -Name "vpnagentd" -ErrorAction SilentlyContinue
            if ($null -eq $AgentProcess) { return $true }
        }
    }

    try {
        Stop-Service -Name $Service.Name -Force -ErrorAction Stop
        Start-Sleep -Seconds 5
        Get-Process -Name "vpnagentd" -ErrorAction SilentlyContinue | Stop-Process -Force
        Start-Sleep -Seconds 2
    } catch {
        Write-Verbose "Force stop failed: $_"
    }

    return ((Get-Service -Name $Service.Name).Status -eq "Stopped")
}

# Starts the VPN agent service and polls until it reaches a running state or the timeout elapses
function Start-VPNAgentService {
    [CmdletBinding()]
    param ()

    $Service = Get-VPNAgentService
    if ($null -eq $Service) { return $false }

    try {
        Start-Service -Name $Service.Name -ErrorAction Stop
    } catch {
        Write-Verbose "Service start failed: $_"
        return $false
    }

    $Timeout = 60
    $Elapsed = 0
    while ($Elapsed -lt $Timeout) {
        Start-Sleep -Seconds 2
        $Elapsed += 2
        if ((Get-Service -Name $Service.Name).Status -eq "Running") {
            return $true
        }
    }
    return $false
}

# Parses active session output from the query session utility to identify the currently logged-on interactive user
function Get-LoggedOnUser {
    [CmdletBinding()]
    param ()

    $Sessions = query session 2>&1
    foreach ($Line in $Sessions) {
        if ($Line -match "Active") {
            $Parts = $Line -split "\s+" | Where-Object { $_ -ne "" }
            if ($Parts.Count -ge 2) { return $Parts[1] }
        }
    }
    return $null
}

# Displays a consent dialog to the logged-on user via a scheduled task running in the interactive session,
# then waits up to 120 seconds for a response before timing out
function Show-UserPrompt {
    [CmdletBinding()]
    param ()

    Unregister-ScheduledTask -TaskName $PromptTaskName `
        -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item $PromptResponseFile -Force -ErrorAction SilentlyContinue
    Remove-Item $PromptScriptFile -Force -ErrorAction SilentlyContinue

    if (-not (Test-Path $FlagFolder)) {
        New-Item -ItemType Directory -Path $FlagFolder -Force | Out-Null
    }

    # Generates a temporary script that renders a Windows Forms dialog and writes the user response to disk
    $PromptCode = @"
Add-Type -AssemblyName System.Windows.Forms
`$Result = [System.Windows.Forms.MessageBox]::Show(
    'A Cisco Secure Client configuration update is required.`n`nYour VPN will be temporarily disconnected.`n`nClick OK to proceed or Cancel to defer to the next check-in.',
    'Cisco Secure Client - Update Required',
    [System.Windows.Forms.MessageBoxButtons]::OKCancel,
    [System.Windows.Forms.MessageBoxIcon]::Information
)
`$Result | Out-File -FilePath '$PromptResponseFile' -Force -Encoding UTF8
"@

    [System.IO.File]::WriteAllText($PromptScriptFile, $PromptCode, [System.Text.Encoding]::UTF8)

    if (-not (Test-Path $PromptScriptFile)) { return "Error" }

    $LoggedOnUser = Get-LoggedOnUser
    if ($null -eq $LoggedOnUser) { return "NoUser" }

    try {
        # Registers and starts a transient scheduled task scoped to the interactive user session
        $Action    = New-ScheduledTaskAction -Execute "powershell.exe" `
                        -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PromptScriptFile`""
        $Principal = New-ScheduledTaskPrincipal -UserId $LoggedOnUser `
                        -LogonType Interactive -RunLevel Limited
        $Settings  = New-ScheduledTaskSettingsSet `
                        -ExecutionTimeLimit (New-TimeSpan -Minutes 2)

        Register-ScheduledTask -TaskName $PromptTaskName -Action $Action `
            -Principal $Principal -Settings $Settings -Force | Out-Null

        Start-Sleep -Seconds 2
        Start-ScheduledTask -TaskName $PromptTaskName
    } catch {
        Write-Verbose "Scheduled task failed: $_"
        Unregister-ScheduledTask -TaskName $PromptTaskName `
            -Confirm:$false -ErrorAction SilentlyContinue
        Remove-Item $PromptScriptFile -Force -ErrorAction SilentlyContinue
        return "Error"
    }

    # Polls for the response file until the user responds or the timeout elapses
    $Timeout = 120
    $Elapsed = 0
    while (-not (Test-Path $PromptResponseFile) -and $Elapsed -lt $Timeout) {
        Start-Sleep -Seconds 2
        $Elapsed += 2
    }

    Unregister-ScheduledTask -TaskName $PromptTaskName `
        -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item $PromptScriptFile -Force -ErrorAction SilentlyContinue

    if (Test-Path $PromptResponseFile) {
        $Response = (Get-Content $PromptResponseFile -Raw).Trim()
        Remove-Item $PromptResponseFile -Force
        return $Response
    }
    return "TimedOut"
}

# Removes the existing OrgInfo.json file if present
function Remove-OrgInfo {
    [CmdletBinding()]
    param ()

    if (Test-Path $JSONFilePath) {
        Remove-Item -Path $JSONFilePath -Force
        Write-Verbose "Removed OrgInfo.json"
    } else {
        Write-Verbose "OrgInfo.json does not exist, skipping removal"
    }
}

# Removes the Umbrella data and SWG subdirectories to clear stale enrollment state
function Remove-UmbrellaSubFolders {
    [CmdletBinding()]
    param ()

    if (Test-Path $UmbrellaDataFolder) {
        Remove-Item -Path $UmbrellaDataFolder -Recurse -Force
        Write-Verbose "Removed Umbrella data folder"
    }
    if (Test-Path $UmbrellaSWGFolder) {
        Remove-Item -Path $UmbrellaSWGFolder -Recurse -Force
        Write-Verbose "Removed Umbrella SWG folder"
    }
}

# Creates the Umbrella directory if absent, then writes the authoritative JSON content
# using UTF-8 encoding without BOM and LF line endings to ensure hash consistency
function Write-OrgInfoJSON {
    [CmdletBinding()]
    param ()

    if (-not (Test-Path $UmbrellaFolder)) {
        New-Item -ItemType Directory -Path $UmbrellaFolder -Force | Out-Null
    }

    $LFContent = $JSONContent -replace "`r`n", "`n"
    $UTF8NoBOM = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($JSONFilePath, $LFContent, $UTF8NoBOM)
    Write-Verbose "Wrote OrgInfo.json (UTF-8 no BOM, LF line endings)"
}

# Executes the full remediation sequence: removes stale OrgInfo, cycles the VPN agent service,
# clears Umbrella subdirectories, and rewrites the authoritative OrgInfo file
function Invoke-Remediation {
    [CmdletBinding()]
    param ()

    Remove-OrgInfo
    Stop-VPNAgentService | Out-Null
    Start-VPNAgentService | Out-Null
    Remove-UmbrellaSubFolders
    Write-OrgInfoJSON
}

# Initializes the remediation result object with default values prior to execution
$RemediationResult = [PSCustomObject]@{
    VPNConnected    = $false
    UserChoice      = "N/A"
    VPNDisconnected = $false
    Remediated      = $false
    FileExists      = $false
}

$RemediationResult.VPNConnected = Get-VPNStatus

# Remediates immediately without user interaction if no active VPN session is detected
if (-not $RemediationResult.VPNConnected) {
    Invoke-Remediation
    $RemediationResult.Remediated = $true
    $RemediationResult.FileExists = Test-Path $JSONFilePath
    if ($RemediationResult.FileExists) { Exit 0 } else { Exit 1 }
}

# Prompts the user for consent before proceeding when a VPN session is active
$RemediationResult.UserChoice = Show-UserPrompt

# Defers remediation if the user did not explicitly approve the operation
if ($RemediationResult.UserChoice -ne "OK") {
    Exit 1
}

# Disconnects the active VPN session and proceeds with the full remediation sequence
$RemediationResult.VPNDisconnected = Disconnect-VPN

Invoke-Remediation
$RemediationResult.Remediated = $true
$RemediationResult.FileExists = Test-Path $JSONFilePath

# Returns exit code 0 if the remediated file is confirmed present, otherwise exit code 1
if ($RemediationResult.FileExists) { Exit 0 } else { Exit 1 }
