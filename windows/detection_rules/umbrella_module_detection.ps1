# =============================================================================
# Script:   umbrella_module_detect.ps1
# Purpose:  Detects whether the Cisco Secure Client Umbrella Roaming Security
#           module is installed on the endpoint and meets the minimum required
#           version. Used by Microsoft Intune as the custom detection rule
#           script for the Cisco Secure Client Umbrella Win32 application
#           deployment.
#
# Overview:
#   This script queries the installed packages on the endpoint for the Cisco
#   Secure Client Umbrella Roaming Security module and evaluates the installed
#   version against a configured minimum version threshold. If a compliant
#   version is found, the script outputs "Installed" and exits with code 0,
#   signaling to Intune that the application is present and no installation is
#   required. If no installed version meets the minimum requirement, the script
#   exits with code 1, prompting Intune to trigger a fresh installation or
#   reinstallation of the module.
#
#   This script is configured as the detection rule script in the Detection
#   Rules step of the Cisco Secure Client Umbrella Win32 app deployment in
#
# Usage:
#   Uploaded directly to the Detection Rules step of the Intune Win32 app
#   deployment. Not intended to be executed manually in most cases, but can
#   be tested locally using PsExec in the SYSTEM account context:
#   ./PsExec.exe -i -s powershell.exe -ExecutionPolicy Bypass -File "umbrella_module_detect.ps1"
#
# Configuration:
#   - Update the minimum version string "5.1.15.287" to match the minimum
#     acceptable version of the Umbrella Roaming Security module for your
#     environment. This value should match the version of the MSI included
#     in the .intunewin package, or a lower version if older installations
#     are considered acceptable.
#
# Exit Codes:
#   0 — Module is installed and meets the minimum version requirement.
#       Intune will take no action.
#   1 — Module is not installed or does not meet the minimum version
#       requirement. Intune will trigger an installation or reinstallation.
# =============================================================================

[CmdletBinding()]
Param ()

# Retrieves all installed packages matching the Cisco Secure Client Umbrella module
$app = @(Get-Package -Name "Cisco Secure Client - Umbrella")

# Evaluates each unique installed version against the minimum required version
$app.Version | Select-Object -Unique | ForEach-Object {
    if ($_ | Where-Object { [System.Version] $_ -ge [System.Version] "5.1.15.287" }) {
        Write-Host "Installed"
        exit 0
    }
}

# Returns exit code 1 if no installed version meets the minimum version requirement
exit 1
