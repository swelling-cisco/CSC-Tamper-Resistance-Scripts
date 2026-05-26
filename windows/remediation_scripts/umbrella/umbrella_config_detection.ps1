# =============================================================================
# Script:   umbrella_config_detection.ps1
# Purpose:  Detects whether the Cisco Secure Client Umbrella Roaming Security
#           OrgInfo.json file is present on the endpoint and matches the
#           expected baseline content. Used by Microsoft Intune as the
#           detection script in the Umbrella Configuration remediation script
#           pair.
#
# Overview:
#   This script evaluates the integrity of the Umbrella OrgInfo.json file
#   deployed to the endpoint by performing two sequential checks:
#
#     1. File presence: Confirms that OrgInfo.json exists at the expected
#        path within the Cisco Secure Client Umbrella directory. If the file
#        is absent, the script immediately exits with code 1 without
#        performing the hash check.
#     2. Hash integrity: Computes the SHA-256 hash of the existing OrgInfo.json
#        and compares it against the expected baseline hash embedded in the
#        script. If the hashes do not match, the file has been modified and
#        the script exits with code 1.
#
#   The script outputs a compressed JSON object summarizing the evaluation
#   result before exiting, including the file presence state, hash match
#   result, expected hash, and actual hash. This output is visible in the
#   Intune remediation script output log and can also be reviewed when
#   testing the script manually.
#
#   If either check fails, Intune will execute the paired
#   umbrella_config_remediation.ps1 script to restore the correct OrgInfo.json
#   to the endpoint.
#
# Usage:
#   Uploaded as the detection script of the Umbrella Configuration remediation
#   script pair in the Intune Remediations console. Can also be tested
#   locally using PsExec in the SYSTEM account context:
#   ./PsExec.exe -i -s powershell.exe -ExecutionPolicy Bypass -File "umbrella_config_detection.ps1"; $LASTEXITCODE
#
# Configuration:
#   - Update $ExpectedHash to match the SHA-256 hash of the authoritative
#     OrgInfo.json that will be written by the paired remediation script.
#     The hash must be calculated from the exact file content written by
#     umbrella_config_remediation.ps1 after it has been finalized, as even
#     a single character difference will produce a different hash value.
#     To calculate the hash of an existing file, run the following command
#     in PowerShell:
#
#       (Get-FileHash -Path "C:\ProgramData\Cisco\Cisco Secure Client\Umbrella\OrgInfo.json" -Algorithm SHA256).Hash
#
#   - $UmbrellaFolder and $JSONFileName define the expected location and
#     filename of the OrgInfo.json file. These values reflect the default
#     Cisco Secure Client Umbrella installation path and should not be
#     modified unless the installation directory has been customized.
#
# Exit Codes:
#   0 — OrgInfo.json is present and its SHA-256 hash matches the expected
#       baseline. Intune will take no action.
#   1 — OrgInfo.json is absent or its hash does not match the expected
#       baseline. Intune will execute the paired remediation script.
# =============================================================================

[CmdletBinding()]
param ()

# Defines the expected file path and SHA-256 hash used to verify Umbrella OrgInfo integrity
$UmbrellaFolder = "C:\ProgramData\Cisco\Cisco Secure Client\Umbrella"
$JSONFileName   = "OrgInfo.json"
$JSONFilePath   = Join-Path -Path $UmbrellaFolder -ChildPath $JSONFileName
$ExpectedHash   = "CA71AB3C90A34C8D5909CB75310BAD201C6BED5F0E4879A0828D6F35EF09DF13"

# Initializes the result object with default values prior to evaluation
$Result = [PSCustomObject]@{
    FileExists    = $false
    HashMatch     = $false
    ExpectedHash  = $ExpectedHash
    ActualHash    = $null
}

# Returns exit code 1 immediately if the OrgInfo file is not present
if (-not (Test-Path $JSONFilePath)) {
    Write-Host ($Result | ConvertTo-Json -Compress)
    Exit 1
}

# Computes the SHA-256 hash of the existing file and compares it against the expected value
$Result.FileExists = $true
$Result.ActualHash = (Get-FileHash -Path $JSONFilePath -Algorithm SHA256).Hash
$Result.HashMatch  = ($Result.ActualHash -eq $ExpectedHash)

Write-Host ($Result | ConvertTo-Json -Compress)

# Returns exit code 1 if the file hash does not match, indicating configuration drift
if (-not $Result.HashMatch) { Exit 1 }

Exit 0
