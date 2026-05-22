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
