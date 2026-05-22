[CmdletBinding()]
Param ()

# Retrieves all installed packages matching the Cisco Secure Client Umbrella module
$app = @(Get-Package -Name "Cisco Secure Client - Umbrella")

# Evaluates each unique installed version against the minimum required version
$app.Version | Select-Object -Unique | ForEach-Object {
    if ($_ | Where-Object { [System.Version] $_ -ge [System.Version] "5.1.15.287" }) {
        Write-Host "Installed"
        exit 0
    }
}

# Returns exit code 1 if no installed version meets the minimum version requirement
exit 1
