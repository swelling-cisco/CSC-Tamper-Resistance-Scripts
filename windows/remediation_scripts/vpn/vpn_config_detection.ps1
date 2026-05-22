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
