# =============================================================================
# Script:   zta_module_install.ps1
# Purpose:  Installs the Cisco Secure Client Zero Trust Access (ZTA) module
#           on Windows endpoints managed through Microsoft Intune.
#
# Overview:
#   This script follows a three-phase sequence:
#     1. Runs disable_lockdown.ps1 to remove any active tamper resistance
#        controls from existing Cisco Secure Client and Duo Desktop components.
#     2. Silently installs the ZTA module MSI, then optionally copies the
#        ZTA enrollment JSON file to the appropriate destination directory
#        on the endpoint for certificate-based ZTA enrollment.
#     3. Runs lockdown.ps1 to reapply tamper resistance controls across all
#        installed Cisco Secure Client and Duo Desktop components.
#
#   The enrollment JSON copy step is only required in environments using
#   certificate-based ZTA enrollment. If your environment uses SAML-based
#   enrollment, the enrollment JSON file does not need to be included in
#   the .intunewin package and the copy step will be skipped automatically
#   if the file is not present. The relevant lines can also be commented
#   out if the enrollment JSON is not needed.
#
#   This script is intended to be deployed as the install command of the
#   Cisco Secure Client ZTA Win32 application in Microsoft Intune.
#
# Usage:
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File "zta_module_install.ps1"
#
# Configuration:
#   - Update $installerName to match the exact filename of the ZTA module
#     MSI included in the .intunewin package for your target version.
#     Example: "cisco-secure-client-win-arm64-5.1.15.4322-zta-predeploy-k9.msi"
#   - Update $enrollmentJsonName to match the exact filename of the ZTA
#     enrollment JSON file included in the .intunewin package, if applicable.
#     Example: "OrgID_ZTA_Enroll_Cert.json"
#   - $enrollmentJsonDestination defines the path on the endpoint where the
#     enrollment JSON will be copied. This value should not be changed.
#
# Requirements:
#   - lockdown.ps1 must be present in the same directory as this script.
#   - disable_lockdown.ps1 must be present in the same directory as this script.
#   - The ZTA module MSI installer must be present in the same directory
#     as this script.
#   - For certificate-based ZTA enrollment, the enrollment JSON file must
#     be present in the same directory as this script.
#   - The AnyConnect VPN Core module must already be installed on the endpoint
#     prior to running this script. In Intune, this is enforced by configuring
#     the VPN Core module as a required dependency of the ZTA Win32 app.
#   - Script must be executed in the SYSTEM account context, as is the case
#     when deployed via Intune.
# =============================================================================

# Define the MSI installer filename (in the same directory as this script)
$installerName = "cisco-secure-client-win-arm64-5.1.15.4322-zta-predeploy-k9.msi"

# Define the enrollment JSON filename (default name; modify as needed)
$enrollmentJsonName = "OrgID_ZTA_Enroll_Cert.json"

# Define the destination path for the enrollment JSON
$enrollmentJsonDestination = "C:\ProgramData\Cisco\Cisco Secure Client\ZTA\enrollment_choices"

# Build the full path to the installer in the current script directory
$installerPath = Join-Path -Path $PSScriptRoot -ChildPath $installerName

# Build the full path to the enrollment JSON in the current script directory
$enrollmentJsonSource = Join-Path -Path $PSScriptRoot -ChildPath $enrollmentJsonName

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

# Install the ZTA module silently with no UI and no restart
$installArgs = "/i `"$installerPath`" /qn /norestart"

# Start the installation process and wait for completion
$process = Start-Process -FilePath "msiexec.exe" -ArgumentList $installArgs -Wait -NoNewWindow -PassThru

if ($process.ExitCode -ne 0) {
    Write-Error "ZTA installation failed with exit code $($process.ExitCode)."
    exit $process.ExitCode
}

# Copy the enrollment JSON file to the destination directory after successful installation
if (-not (Test-Path $enrollmentJsonSource)) {
    Write-Error "Enrollment JSON file not found: $enrollmentJsonSource. Skipping copy."
}
else {
    try {
        # Create the destination directory if it does not already exist
        if (-not (Test-Path $enrollmentJsonDestination)) {
            New-Item -ItemType Directory -Path $enrollmentJsonDestination -Force | Out-Null
            Write-Output "Created destination directory: $enrollmentJsonDestination"
        }

        Copy-Item -Path $enrollmentJsonSource -Destination $enrollmentJsonDestination -Force
        Write-Output "Enrollment JSON copied successfully to: $enrollmentJsonDestination"
    }
    catch {
        Write-Error "Failed to copy enrollment JSON file: $_"
    }
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
