# =============================================================================
# Script:   zta_module_detect.ps1
# Purpose:  Detects whether the Cisco Secure Client Zero Trust Access (ZTA)
#           module and Duo Desktop are installed on the endpoint and meet the
#           required installation criteria. Used by Microsoft Intune as the
#           custom detection rule script for the Cisco Secure Client ZTA Win32
#           application deployment.
#
# Overview:
#   This script performs two independent compliance checks before reporting
#   the installation state to Intune:
#
#     1. ZTA module version: Queries the installed packages on the endpoint
#        for the Cisco Secure Client Zero Trust Access module and evaluates
#        the installed version against a configured minimum version threshold.
#     2. Duo Desktop presence: Queries the installed packages on the endpoint
#        for Duo Desktop and confirms that it is present, regardless of version.
#        Duo Desktop is a dependency of the ZTA module and is installed
#        alongside it by the ZTA module MSI. If Duo Desktop is absent, the
#        script treats the ZTA installation as non-compliant and triggers a
#        reinstallation of the ZTA module, which will restore Duo Desktop as
#        part of the installation process.
#
#   Both conditions must be satisfied for the script to exit with code 0. If
#   either check fails, the script reports the specific compliance gap and
#   exits with code 1, prompting Intune to trigger a reinstallation of the
#   ZTA module. The reinstallation will restore both the ZTA module and Duo
#   Desktop to a compliant state.
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
#   - Update the minimum version string "5.1.15.4322" to match the minimum
#     acceptable version of the ZTA module for your environment. This value
#     should match the version of the MSI included in the .intunewin package,
#     or a lower version if older installations are considered acceptable.
#   - No minimum version is enforced for Duo Desktop. The script only confirms
#     that Duo Desktop is present. If a minimum Duo Desktop version is required
#     in your environment, the version check logic from the ZTA compliance
#     block can be adapted and applied to the Duo Desktop check accordingly.
#
# Exit Codes:
#   0 — ZTA module is installed and meets the minimum version requirement,
#       and Duo Desktop is present. Intune will take no action.
#   1 — ZTA module is not installed, does not meet the minimum version
#       requirement, or Duo Desktop is not present. Intune will trigger an
#       installation or reinstallation of the ZTA module.
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
