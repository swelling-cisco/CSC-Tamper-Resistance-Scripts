# Define the MSI installer filename (in the same directory as this script)
$installerName = "cisco-secure-client-win-arm64-5.1.15.287-core-vpn-predeploy-k9.msi"

# Build the full path to the installer in the current script directory
$installerPath = Join-Path -Path $PSScriptRoot -ChildPath $installerName

# Define the path to the disable lockdown script (in the same directory)
$disableLockdownScriptPath = Join-Path -Path $PSScriptRoot -ChildPath "disable_lockdown.ps1"

# Execute the disable lockdown script with bypassed execution policy
try {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $disableLockdownScriptPath
    Write-Output "Lockdown disable script executed successfully."
}
catch {
    Write-Error "Failed to execute lockdown disable script: $_"
    exit 1
}

# Uninstall other Cisco Secure Client modules and Duo Desktop
$secureClientEntries = Get-ItemProperty `
    HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*, `
    HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* `
    -ErrorAction SilentlyContinue |
Where-Object { ($_.DisplayName -like "Cisco Secure Client*" -and $_.DisplayName -notlike "*VPN*") -or $_.DisplayName -like "Duo Desktop*" }

if ($null -ne $secureClientEntries) {
    $secureClientEntries | ForEach-Object {
        $secureClientEntry       = $_
        $secureClientGuid        = $secureClientEntry.PSChildName
        $secureClientVersion     = $secureClientEntry.DisplayVersion
        $secureClientDisplayName = $secureClientEntry.DisplayName

        Write-Output "Found '$secureClientDisplayName' version $secureClientVersion with GUID: $secureClientGuid. Proceeding with uninstallation."

        $secureClientUninstallArgs = "/x `"$secureClientGuid`" /qn /norestart"
        $secureClientProcess = Start-Process -FilePath "msiexec.exe" -ArgumentList $secureClientUninstallArgs -Wait -NoNewWindow -PassThru

        if ($secureClientProcess.ExitCode -eq 0) {
            Write-Output "'$secureClientDisplayName' version $secureClientVersion uninstalled successfully."
        }
        elseif ($secureClientProcess.ExitCode -eq 1605) {
            # 1605 means the product is not installed — likely a stale registry keynfrom a previous upgrade
            Write-Output "'$secureClientDisplayName' version $secureClientVersion (GUID: $secureClientGuid) is not installed. Stale registry key detected, skipping."
        }
        else {
            Write-Error "'$secureClientDisplayName' version $secureClientVersion uninstallation failed with exit code $($secureClientProcess.ExitCode)."
            exit $secureClientProcess.ExitCode
        }
    }
}
else {
    Write-Output "No Cisco Secure Client or Duo Desktop modules found. Skipping uninstallation."
}

# Uninstall the AnyConnect VPN module silently with no UI and no restart
$uninstallArgs = "/x `"$installerPath`" /qn /norestart"

# Start the uninstall process and wait for completion
$process = Start-Process -FilePath "msiexec.exe" -ArgumentList $uninstallArgs -Wait -NoNewWindow -PassThru

if ($process.ExitCode -ne 0) {
    Write-Error "AnyConnect VPN uninstallation failed with exit code $($process.ExitCode)."
    exit $process.ExitCode
}

exit 0
