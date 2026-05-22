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
