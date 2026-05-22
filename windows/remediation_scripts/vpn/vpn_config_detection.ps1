# =============================================================================
# Script:   vpn_config_detection.ps1
# Purpose:  Detects whether the Cisco Secure Client AnyConnect VPN connection
#           profile is present on the endpoint and matches the expected
#           baseline content. Used by Microsoft Intune as the detection script
#           in the VPN Configuration remediation script pair.
#
# Overview:
#   This script evaluates the integrity of the VPN XML profile deployed to
#   the endpoint by performing two sequential checks:
#
#     1. File presence: Confirms that the VPN XML profile exists at the
#        expected path within the Cisco Secure Client VPN profile directory.
#        If the file is absent, the script immediately exits with code 1
#        without performing the hash check.
#     2. Hash integrity: Computes the SHA-256 hash of the existing VPN XML
#        profile and compares it against the expected baseline hash embedded
#        in the script. If the hashes do not match, the file has been modified
#        and the script exits with code 1.
#
#   The script outputs a compressed JSON object summarizing the evaluation
#   result before exiting, including the file presence state, hash match
#   result, expected hash, and actual hash. This output is visible in the
#   Intune remediation script output log and can also be reviewed when
#   testing the script manually.
#
#   If either check fails, Intune will execute the paired
#   vpn_config_remediation.ps1 script to restore the correct VPN profile
#   to the endpoint.
#
# Usage:
#   Uploaded as the detection script of the VPN Configuration remediation
#   script pair in the Intune Remediations console. Can also be tested
#   locally using PsExec in the SYSTEM account context:
#   ./PsExec.exe -i -s powershell.exe -ExecutionPolicy Bypass -File "vpn_config_detection.ps1"; $LASTEXITCODE
#
# Configuration:
#   - Update $XMLFileName to match the filename of the VPN XML profile used
#     in your environment.
#     Example: "Cert_Profile.xml"
#   - Update $ExpectedHash to match the SHA-256 hash of the authoritative
#     VPN XML profile that will be written by the paired remediation script.
#     The hash must be calculated from the exact file content written by
#     vpn_config_remediation.ps1 after it has been finalized, as even a
#     single character difference will produce a different hash value.
#     To calculate the hash of an existing file, run the following command
#     in PowerShell:
#
#       (Get-FileHash -Path "C:\path\to\Cert_Profile.xml" -Algorithm SHA256).Hash
#
#   - $VPNProfileFolder defines the directory where the VPN XML profile is
#     expected to reside. This value should not be changed.
#
# Exit Codes:
#   0 — The VPN XML profile is present and its SHA-256 hash matches the
#       expected baseline. Intune will take no action.
#   1 — The VPN XML profile is absent or its hash does not match the
#       expected baseline. Intune will execute the paired remediation script.
# =============================================================================

[CmdletBinding()]
param ()

# Defines the expected file path and SHA-256 hash used to verify VPN profile integrity
$VPNProfileFolder = "C:\ProgramData\Cisco\Cisco Secure Client\VPN\Profile"
$XMLFileName      = "Cert_Profile.xml"
$XMLFilePath      = Join-Path -Path $VPNProfileFolder -ChildPath $XMLFileName
$ExpectedHash     = "676024C3E032549A24908A32F327F32696B1AC4F0D26748CB88FC7413CFB778B"

# Initializes the result object with default values prior to evaluation
$Result = [PSCustomObject]@{
    FileExists   = $false
    HashMatch    = $false
    ExpectedHash = $ExpectedHash
    ActualHash   = $null
}

# Returns exit code 1 immediately if the VPN profile file is not present
if (-not (Test-Path $XMLFilePath)) {
    Write-Host ($Result | ConvertTo-Json -Compress)
    Exit 1
}

# Computes the SHA-256 hash of the existing file and compares it against the expected value
$Result.FileExists = $true
$Result.ActualHash = (Get-FileHash -Path $XMLFilePath -Algorithm SHA256).Hash
$Result.HashMatch  = ($Result.ActualHash -eq $ExpectedHash)

Write-Host ($Result | ConvertTo-Json -Compress)

# Returns exit code 1 if the file hash does not match, indicating configuration drift
if (-not $Result.HashMatch) { Exit 1 }

Exit 0
