# =============================================================================
# Script:   zta_config_remediation.ps1
# Purpose:  Restores the Cisco Secure Client Zero Trust Access (ZTA) enrollment
#           configuration file to its authoritative baseline state and removes
#           any extraneous JSON files from the enrollment folder on Windows
#           endpoints when configuration drift is detected. Used by Microsoft
#           Intune as the remediation script in the ZTA Configuration
#           remediation script pair.
#
# Overview:
#   This script restores the ZTA enrollment configuration by performing the
#   following steps:
#
#     1. Removes any extraneous JSON files from the enrollment_choices folder
#        that do not match the authoritative enrollment filename, eliminating
#        any files that could cause ZTA enrollment conflicts.
#     2. Removes the existing authoritative enrollment JSON file if present,
#        ensuring a clean write.
#     3. Creates the enrollment_choices directory if it does not already exist.
#     4. Writes the authoritative ZTA enrollment JSON content to the correct
#        path using UTF-8 encoding.
#
#   This script is executed by Intune only when the paired
#   zta_config_detection.ps1 script exits with code 1, indicating that the
#   enrollment JSON is absent, does not match the expected baseline hash,
#   or extraneous JSON files are present in the enrollment folder.
#
# Usage:
#   Uploaded as the remediation script of the ZTA Configuration remediation
#   script pair in the Intune Remediations console. Can also be tested
#   locally using PsExec in the SYSTEM account context:
#   ./PsExec.exe -i -s powershell.exe -ExecutionPolicy Bypass -File "zta_config_remediation.ps1"; $LASTEXITCODE
#
# Configuration:
#   - Update $JSONFileName to match the exact filename of the ZTA enrollment
#     JSON file used in your environment. This filename is derived from the
#     organization ID in your Cisco Secure Access environment and is embedded
#     in the filename of the enrollment JSON downloaded from the dashboard.
#     Example: "OrgID_ZTA_Enroll_Cert.json"
#     This value must match the filename configured in the paired
#     zta_config_detection.ps1 script.
#   - Update the $JSONContent heredoc block with the complete and authoritative
#     content of the ZTA enrollment JSON file for your environment. The file
#     content must be placed between the @' and '@ delimiters exactly as it
#     should appear on disk. Do not add or remove whitespace, line breaks, or
#     characters outside of those delimiters, as any change to the content
#     will alter the SHA-256 hash of the written file and cause the paired
#     detection script to continuously report a mismatch.
#     The ZTA enrollment JSON file can be downloaded from the Cisco Secure
#     Access dashboard by navigating to Connect > Essentials > End User
#     Connectivity, clicking the Zero Trust Access tab, and downloading the
#     enrollment configuration file from the Enrollment Methods section.
#   - After finalizing the $JSONContent block, recalculate the expected
#     SHA-256 hash by deploying this remediation script to a test device and
#     running the following command in PowerShell to obtain the hash of the
#     written file:
#
#       (Get-FileHash -Path "C:\ProgramData\Cisco\Cisco Secure Client\ZTA\enrollment_choices\OrgID_ZTA_Enroll_Cert.json" -Algorithm SHA256).Hash
#
#     Enter the resulting value as $ExpectedHash in the paired
#     zta_config_detection.ps1 script. If the $JSONContent block is updated
#     in the future, this process must be repeated and the $ExpectedHash
#     value must be updated accordingly.
#   - $ZTAEnrollmentFolder defines the directory where the enrollment JSON
#     file will be written. This value reflects the default Cisco Secure
#     Client ZTA installation path and should not be modified.
#
# Exit Codes:
#   0 — The ZTA enrollment JSON file has been successfully written to the
#       expected path and confirmed as present on disk. Intune will record
#       the remediation as successful.
#   1 — The ZTA enrollment JSON file was not found on disk after the write
#       operation completed, indicating that the remediation did not succeed.
#       Intune will record the remediation as failed and retry on the next
#       cycle.
# =============================================================================

[CmdletBinding()]
param ()

# Defines the target directory and file path for the ZTA enrollment configuration
$ZTAEnrollmentFolder = "C:\ProgramData\Cisco\Cisco Secure Client\ZTA\enrollment_choices"
$JSONFileName        = "OrgID_ZTA_Enroll_Cert.json"
$JSONFilePath        = Join-Path -Path $ZTAEnrollmentFolder -ChildPath $JSONFileName

# Defines the authoritative ZTA enrollment JSON content to be written during remediation
$JSONContent = @'
{
    "version": 1,
    "comment": "Auto Enrollment Configuration",
    "signed_payload": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJkdW1teSIsIm5hbWUiOiJleGFtcGxlIiwiaWF0IjoxNzczMzYzMDk1fQ.ZHVtbXlfc2lnbmF0dXJl"
}
'@

# Removes any JSON files in the enrollment folder that do not match the authoritative file name,
# returning a list of the files that were successfully deleted
function Remove-ExtraZTAFiles {
    [CmdletBinding()]
    param ()

    if (-not (Test-Path $ZTAEnrollmentFolder)) {
        Write-Verbose "ZTA enrollment folder does not exist, skipping cleanup"
        return @()
    }

    $RemovedFiles = @()
    $AllJSONFiles = Get-ChildItem -Path $ZTAEnrollmentFolder -Filter "*.json" -ErrorAction SilentlyContinue

    foreach ($File in $AllJSONFiles) {
        if ($File.Name -ne $JSONFileName) {
            try {
                Remove-Item -Path $File.FullName -Force -ErrorAction Stop
                Write-Verbose "Removed extra file: $($File.Name)"
                $RemovedFiles += $File.Name
            } catch {
                Write-Verbose "Failed to remove $($File.Name): $_"
            }
        }
    }

    return $RemovedFiles
}

# Removes the existing authoritative enrollment JSON file if present, suppressing errors if it does not exist
function Remove-ZTAEnrollmentJSON {
    [CmdletBinding()]
    param ()

    if (Test-Path $JSONFilePath) {
        try {
            Remove-Item -Path $JSONFilePath -Force -ErrorAction Stop
            Write-Verbose "Removed $JSONFileName"
        } catch {
            Write-Verbose "Failed to remove $JSONFileName : $_"
        }
    } else {
        Write-Verbose "$JSONFileName does not exist, skipping removal"
    }
}

# Creates the enrollment directory if absent, then writes the authoritative JSON content
# using UTF-8 encoding without BOM and LF line endings to ensure hash consistency
function Write-ZTAEnrollmentJSON {
    [CmdletBinding()]
    param ()

    if (-not (Test-Path $ZTAEnrollmentFolder)) {
        New-Item -ItemType Directory -Path $ZTAEnrollmentFolder -Force | Out-Null
        Write-Verbose "Created ZTA enrollment folder"
    }

    try {
        $LFContent = ($JSONContent -replace "`r`n", "`n")
        $UTF8NoBOM = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($JSONFilePath, $LFContent, $UTF8NoBOM)
        Write-Verbose "Wrote $JSONFileName (UTF-8 no BOM, LF line endings)"
    } catch {
        Write-Verbose "Failed to write $JSONFileName : $_"
    }
}

# Initializes the remediation result object with default values prior to execution
$RemediationResult = [PSCustomObject]@{
    ExtraFilesRemoved   = @()
    TargetFileRemoved   = $false
    TargetFileWritten   = $false
    FileExists          = $false
}

# Removes any extraneous JSON files from the enrollment folder before rewriting the authoritative file
$RemediationResult.ExtraFilesRemoved = Remove-ExtraZTAFiles

# Removes the existing enrollment file and confirms deletion before proceeding
Remove-ZTAEnrollmentJSON
$RemediationResult.TargetFileRemoved = -not (Test-Path $JSONFilePath)

# Writes the authoritative enrollment file and confirms the file is present on disk
Write-ZTAEnrollmentJSON
$RemediationResult.TargetFileWritten = Test-Path $JSONFilePath
$RemediationResult.FileExists        = Test-Path $JSONFilePath

# Returns exit code 0 if the remediated file is confirmed present, otherwise exit code 1
if ($RemediationResult.FileExists) { Exit 0 } else { Exit 1 }
