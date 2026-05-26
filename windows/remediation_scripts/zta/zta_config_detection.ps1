# =============================================================================
# Script:   zta_config_detection.ps1
# Purpose:  Detects whether the Cisco Secure Client Zero Trust Access (ZTA)
#           enrollment configuration file is present on the endpoint, matches
#           the expected baseline content, and that no extraneous JSON files
#           are present in the enrollment folder. Used by Microsoft Intune as
#           the detection script in the ZTA Configuration remediation script
#           pair.
#
# Overview:
#   This script evaluates the integrity of the ZTA enrollment configuration
#   by performing four sequential checks:
#
#     1. Folder presence: Confirms that the ZTA enrollment_choices directory
#        exists at the expected path. If the folder is absent, the script
#        immediately exits with code 1 without performing further checks.
#     2. File presence: Confirms that the authoritative ZTA enrollment JSON
#        file exists within the enrollment_choices folder. If the file is
#        absent, the script immediately exits with code 1 without performing
#        the hash check.
#     3. Hash integrity: Computes the SHA-256 hash of the existing enrollment
#        JSON file and compares it against the expected baseline hash embedded
#        in the script. If the hashes do not match, the file has been modified
#        and the script will exit with code 1 after completing all checks.
#     4. Extraneous file detection: Scans the enrollment_choices folder for
#        any JSON files other than the authoritative enrollment file. The
#        presence of additional JSON files in this folder can cause ZTA
#        enrollment conflicts. If any extraneous files are found, the script
#        will exit with code 1.
#
#   The script outputs a compressed JSON object summarizing the evaluation
#   result before exiting, including folder and file presence state, hash
#   match result, expected and actual hashes, and details of any extraneous
#   files detected. This output is visible in the Intune remediation script
#   output log and can also be reviewed when testing the script manually.
#
#   If any check fails, Intune will execute the paired
#   zta_config_remediation.ps1 script to restore the correct enrollment
#   configuration and remove any extraneous files.
#
# Usage:
#   Uploaded as the detection script of the ZTA Configuration remediation
#   script pair in the Intune Remediations console. Can also be tested
#   locally using PsExec in the SYSTEM account context:
#   ./PsExec.exe -i -s powershell.exe -ExecutionPolicy Bypass -File "zta_config_detection.ps1"; $LASTEXITCODE
#
# Configuration:
#   - Update $JSONFileName to match the exact filename of the ZTA enrollment
#     JSON file used in your environment. This filename is derived from the
#     organization ID in your Cisco Secure Access environment and is embedded
#     in the filename of the enrollment JSON downloaded from the dashboard.
#     Example: "OrgID_ZTA_Enroll_Cert.json"
#     This value must match the filename configured in the paired
#     zta_config_remediation.ps1 script.
#   - Update $ExpectedHash to match the SHA-256 hash of the authoritative
#     ZTA enrollment JSON file that will be written by the paired remediation
#     script. The hash must be calculated from the exact file content written
#     by zta_config_remediation.ps1 after it has been finalized, as even a
#     single character difference will produce a different hash value.
#     To calculate the hash of an existing file, run the following command
#     in PowerShell:
#
#       (Get-FileHash -Path "C:\ProgramData\Cisco\Cisco Secure Client\ZTA\enrollment_choices\OrgID_ZTA_Enroll_Cert.json" -Algorithm SHA256).Hash
#
#   - $ZTAEnrollmentFolder defines the expected location of the enrollment
#     JSON file. This value reflects the default Cisco Secure Client ZTA
#     installation path and should not be modified.
#
# Exit Codes:
#   0 — The ZTA enrollment folder and JSON file are present, the SHA-256
#       hash matches the expected baseline, and no extraneous JSON files
#       are present in the enrollment folder. Intune will take no action.
#   1 — The enrollment folder or JSON file is absent, the hash does not
#       match the expected baseline, or extraneous JSON files are present
#       in the enrollment folder. Intune will execute the paired remediation
#       script.
# =============================================================================

[CmdletBinding()]
param ()

# Defines the expected folder path, file path, and SHA-256 hash used to verify ZTA enrollment configuration integrity
$ZTAEnrollmentFolder = "C:\ProgramData\Cisco\Cisco Secure Client\ZTA\enrollment_choices"
$JSONFileName        = "OrgID_ZTA_Enroll_Cert.json"
$JSONFilePath        = Join-Path -Path $ZTAEnrollmentFolder -ChildPath $JSONFileName
$ExpectedHash        = "5674DD6F55527CD2711490D46F7D256AA75A0431F158840EA71BE9A821C62BED"

# Initializes the result object with default values prior to evaluation
$Result = [PSCustomObject]@{
    FolderExists    = $false
    FileExists      = $false
    HashMatch       = $false
    ExpectedHash    = $ExpectedHash
    ActualHash      = $null
    ExtraFilesFound = $false
    ExtraFileCount  = 0
    ExtraFileNames  = @()
}

# Returns exit code 1 immediately if the ZTA enrollment folder is not present
if (-not (Test-Path $ZTAEnrollmentFolder)) {
    Write-Host ($Result | ConvertTo-Json -Compress)
    Exit 1
}

$Result.FolderExists = $true

# Returns exit code 1 immediately if the enrollment JSON file is not present
if (-not (Test-Path $JSONFilePath)) {
    Write-Host ($Result | ConvertTo-Json -Compress)
    Exit 1
}

$Result.FileExists = $true

# Computes the SHA-256 hash of the existing file and compares it against the expected value
$Result.ActualHash = (Get-FileHash -Path $JSONFilePath -Algorithm SHA256).Hash
$Result.HashMatch  = ($Result.ActualHash -eq $ExpectedHash)

# Identifies any JSON files in the enrollment folder that are not the authoritative enrollment file
$AllJSONFiles = Get-ChildItem -Path $ZTAEnrollmentFolder -Filter "*.json" -ErrorAction SilentlyContinue
$ExtraFiles   = $AllJSONFiles | Where-Object { $_.Name -ne $JSONFileName }

if ($null -ne $ExtraFiles -and @($ExtraFiles).Count -gt 0) {
    $Result.ExtraFilesFound = $true
    $Result.ExtraFileCount  = @($ExtraFiles).Count
    $Result.ExtraFileNames  = @($ExtraFiles | ForEach-Object { $_.Name })
}

Write-Host ($Result | ConvertTo-Json -Compress)

# Returns exit code 1 if the file hash does not match, indicating configuration drift
if (-not $Result.HashMatch) { Exit 1 }

# Returns exit code 1 if unexpected JSON files are present in the enrollment folder
if ($Result.ExtraFilesFound) { Exit 1 }

Exit 0
