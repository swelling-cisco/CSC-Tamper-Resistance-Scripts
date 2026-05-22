# Define the MSI installer filename (in the same directory as this script)
$installerName = "cisco-secure-client-win-arm64-5.1.15.4322-zta-predeploy-k9.msi"

# Build the full path to the installer in the current script directory
$installerPath = Join-Path -Path $PSScriptRoot -ChildPath $installerName

# Define the path to the lockdown remediation script (in the same directory)
$lockdownScriptPath = Join-Path -Path $PSScriptRoot -ChildPath "lockdown.ps1"

# Define the path to the disable lockdown script (in the same directory)
$disableLockdownScriptPath = Join-Path -Path $PSScriptRoot -ChildPath "disable_lockdown.ps1"

# Execute the disable lockdown script with bypassed execution policy
try {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $disableLockdownScriptPath
    Write-Output "Lockdown disable script executed successfully."
}
catch {
    Write-Error "Failed to execute lockdown disable script: $_"
    exit 1
}

# Uninstall the ZTA module silently with no UI and no restart
$uninstallArgs = "/x `"$installerPath`" /qn /norestart"

# Start the ZTA uninstall process and wait for completion
$process = Start-Process -FilePath "msiexec.exe" -ArgumentList $uninstallArgs -Wait -NoNewWindow -PassThru

if ($process.ExitCode -ne 0) {
    Write-Error "ZTA uninstallation failed with exit code $($process.ExitCode)."
    exit $process.ExitCode
}

# Uninstall Duo Desktop
$duoDesktopEntries = Get-ItemProperty `
    HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*, `
    HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* `
    -ErrorAction SilentlyContinue |
Where-Object { $_.DisplayName -like "Duo Desktop*" }

if ($null -ne $duoDesktopEntries) {
    $duoDesktopEntries | ForEach-Object {
        $duoEntry   = $_
        $duoGuid    = $duoEntry.PSChildName
        $duoVersion = $duoEntry.DisplayVersion

        Write-Output "Found Duo Desktop version $duoVersion with GUID: $duoGuid. Proceeding with uninstallation."

        $duoUninstallArgs = "/x `"$duoGuid`" /qn /norestart"
        $duoProcess = Start-Process -FilePath "msiexec.exe" -ArgumentList $duoUninstallArgs -Wait -NoNewWindow -PassThru

        if ($duoProcess.ExitCode -eq 0) {
            Write-Output "Duo Desktop version $duoVersion uninstalled successfully."
        }
        elseif ($duoProcess.ExitCode -eq 1605) {
            # 1605 means the product is not installed — likely a stale registry key from a previous upgrade
            Write-Output "Duo Desktop version $duoVersion (GUID: $duoGuid) is not installed. Stale registry key detected, skipping."
        }
        else {
            Write-Error "Duo Desktop version $duoVersion uninstallation failed with exit code $($duoProcess.ExitCode)."
            exit $duoProcess.ExitCode
        }
    }
}
else {
    Write-Output "Duo Desktop not found. Skipping uninstallation."
}

# Execute the lockdown remediation script with bypassed execution policy
try {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $lockdownScriptPath
    Write-Output "Lockdown remediation script executed successfully."
}
catch {
    Write-Error "Failed to execute lockdown remediation script: $_"
    exit 1
}

exit 0
