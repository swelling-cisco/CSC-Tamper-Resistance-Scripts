# =============================================================================
# Script:   umbrella_module_install.ps1
# Purpose:  Installs the Cisco Secure Client Umbrella Roaming Security module
#           on Windows endpoints managed through Microsoft Intune.
#
# Overview:
#   This script follows a three-phase sequence:
#     1. Runs disable_lockdown.ps1 to remove any active tamper resistance
#        controls from existing Cisco Secure Client and Duo Desktop components.
#     2. Silently installs the Umbrella Roaming Security module MSI.
#     3. Runs lockdown.ps1 to reapply tamper resistance controls across all
#        installed Cisco Secure Client and Duo Desktop components.
#
#   This script is intended to be deployed as the install command of the
#   Cisco Secure Client Umbrella Win32 application in Microsoft Intune.
#
# Usage:
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File "umbrella_module_install.ps1"
#
# Configuration:
#   - Update $installerName to match the exact filename of the Umbrella
#     Roaming Security MSI included in the .intunewin package for your
#     target version.
#     Example: "cisco-secure-client-win-arm64-5.1.15.287-umbrella-predeploy-k9.msi"
#
# Requirements:
#   - lockdown.ps1 must be present in the same directory as this script.
#   - disable_lockdown.ps1 must be present in the same directory as this script.
#   - The Umbrella Roaming Security MSI installer must be present in the same
#     directory as this script.
#   - The AnyConnect VPN Core module must already be installed on the endpoint
#     prior to running this script. In Intune, this is enforced by configuring
#     the VPN Core module as a required dependency of the Umbrella Win32 app.
#   - Script must be executed in the SYSTEM account context, as is the case
#     when deployed via Intune.
# =============================================================================

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

# Install the Umbrella module silently with no UI and no restart
$installArgs = "/i `"$installerPath`" /qn /norestart"

# Start the installation process and wait for completion
$process = Start-Process -FilePath "msiexec.exe" -ArgumentList $installArgs -Wait -NoNewWindow -PassThru

if ($process.ExitCode -ne 0) {
    Write-Error "Umbrella installation failed with exit code $($process.ExitCode)."
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
