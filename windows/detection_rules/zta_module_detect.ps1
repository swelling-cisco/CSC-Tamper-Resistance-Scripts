# =============================================================================
# Script:   zta_module_detect.ps1
# Purpose:  Detects whether the Cisco Secure Client Zero Trust Access (ZTA)
#           module is installed on the endpoint and meets the minimum required
#           version. Used by Microsoft Intune as the custom detection rule
#           script for the Cisco Secure Client ZTA Win32 application deployment.
#
# Overview:
#   This script queries the installed packages on the endpoint for the Cisco
#   Secure Client Zero Trust Access module and evaluates the installed version
#   against a configured minimum version threshold. If a compliant version is
#   found, the script outputs "Installed" and exits with code 0, signaling to
#   Intune that the application is present and no installation is required. If
#   no installed version meets the minimum requirement, the script exits with
#   code 1, prompting Intune to trigger a fresh installation or reinstallation
#   of the module.
#
#   This script is configured as the detection rule script in the Detection
#   Rules step of the Cisco Secure Client ZTA Win32 app deployment in Intune.
#
# Usage:
#   Uploaded directly to the Detection Rules step of the Intune Win32 app
#   deployment. Not intended to be executed manually in most cases, but can
#   be tested locally using PsExec in the SYSTEM account context:
#   ./PsExec.exe -i -s powershell.exe -ExecutionPolicy Bypass -File "zta_module_detect.ps1"
#
# Configuration:
#   - Update the minimum version string "5.1.15.287" to match the minimum
#     acceptable version of the ZTA module for your environment. This value
#     should match the version of the MSI included in the .intunewin package,
#     or a lower version if older installations are considered acceptable.
#
# Exit Codes:
#   0 — Module is installed and meets the minimum version requirement.
#       Intune will take no action.
#   1 — Module is not installed or does not meet the minimum version
#       requirement. Intune will trigger an installation or reinstallation.
# =============================================================================

[CmdletBinding()]
Param ()

# Retrieves all installed packages matching the Cisco Secure Client Zero Trust Access module
$zta = @(Get-Package -Name "Cisco Secure Client - Zero Trust Access" -ErrorAction SilentlyContinue)

$ztaCompliant = $false

# Evaluates each unique installed ZTA version against the minimum required version
$zta.Version | Select-Object -Unique | ForEach-Object {
    if ($_ | Where-Object { [System.Version]$_ -ge [System.Version]"5.1.15.4322" }) {
        $ztaCompliant = $true
    }
}

# Retrieves all installed packages matching Duo Desktop
$duo = @(Get-Package -Name "Duo Desktop" -ErrorAction SilentlyContinue)

$duoInstalled = $false

# Confirms Duo Desktop is present regardless of version
if ($duo.Count -gt 0) {
    $duoInstalled = $true
}

# Returns exit code 0 only when both the ZTA module and Duo Desktop compliance conditions are satisfied
if ($ztaCompliant -and $duoInstalled) {
    Write-Host "Installed"
    exit 0
} else {
    # Reports the specific compliance gap for each failing condition before exiting
    if (-not $ztaCompliant) {
        Write-Host "Non-Compliant: Cisco Secure Client ZTA module is missing or below minimum version."
    }
    if (-not $duoInstalled) {
        Write-Host "Non-Compliant: Duo Desktop is not installed. Reinstalling ZTA module will remediate."
    }
    exit 1
}
