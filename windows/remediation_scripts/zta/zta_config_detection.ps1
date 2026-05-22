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
