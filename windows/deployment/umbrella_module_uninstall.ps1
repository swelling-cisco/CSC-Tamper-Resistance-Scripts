# Define the MSI installer filename (in the same directory as this script)
$installerName = "cisco-secure-client-win-arm64-5.1.15.287-umbrella-predeploy-k9.msi"

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

# Uninstall the Umbrella module silently with no UI and no restart
$uninstallArgs = "/x `"$installerPath`" /qn /norestart"

# Start the uninstall process and wait for completion
$process = Start-Process -FilePath "msiexec.exe" -ArgumentList $uninstallArgs -Wait -NoNewWindow -PassThru

if ($process.ExitCode -ne 0) {
    Write-Error "Umbrella uninstallation failed with exit code $($process.ExitCode)."
    exit $process.ExitCode
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
