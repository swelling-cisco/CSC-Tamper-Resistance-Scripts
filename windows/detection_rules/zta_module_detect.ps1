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
