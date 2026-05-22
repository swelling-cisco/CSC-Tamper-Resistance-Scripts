# Define the MSI installer filename (in the same directory as this script)
$installerName = "cisco-secure-client-win-arm64-5.1.15.4322-zta-predeploy-k9.msi"

# Define the enrollment JSON filename (default name; modify as needed)
$enrollmentJsonName = "OrgID_ZTA_Enroll_Cert.json"

# Define the destination path for the enrollment JSON
$enrollmentJsonDestination = "C:\ProgramData\Cisco\Cisco Secure Client\ZTA\enrollment_choices"

# Build the full path to the installer in the current script directory
$installerPath = Join-Path -Path $PSScriptRoot -ChildPath $installerName

# Build the full path to the enrollment JSON in the current script directory
$enrollmentJsonSource = Join-Path -Path $PSScriptRoot -ChildPath $enrollmentJsonName

# Define the path to the lockdown remediation script (in the same directory)
$lockdownScriptPath = Join-Path -Path $PSScriptRoot -ChildPath "lockdown.ps1"

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

# Install the ZTA module silently with no UI and no restart
$installArgs = "/i `"$installerPath`" /qn /norestart"

# Start the installation process and wait for completion
$process = Start-Process -FilePath "msiexec.exe" -ArgumentList $installArgs -Wait -NoNewWindow -PassThru

if ($process.ExitCode -ne 0) {
    Write-Error "ZTA installation failed with exit code $($process.ExitCode)."
    exit $process.ExitCode
}

# Copy the enrollment JSON file to the destination directory after successful installation
if (-not (Test-Path $enrollmentJsonSource)) {
    Write-Error "Enrollment JSON file not found: $enrollmentJsonSource. Skipping copy."
}
else {
    try {
        # Create the destination directory if it does not already exist
        if (-not (Test-Path $enrollmentJsonDestination)) {
            New-Item -ItemType Directory -Path $enrollmentJsonDestination -Force | Out-Null
            Write-Output "Created destination directory: $enrollmentJsonDestination"
        }

        Copy-Item -Path $enrollmentJsonSource -Destination $enrollmentJsonDestination -Force
        Write-Output "Enrollment JSON copied successfully to: $enrollmentJsonDestination"
    }
    catch {
        Write-Error "Failed to copy enrollment JSON file: $_"
    }
}

# Execute the lockdown remediation script with bypassed execution policy
try {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $lockdownScriptPath
    Write-Output "Lockdown remediation script executed successfully."
}
catch {
    Write-Error "Failed to execute lockdown remediation script: $_"
    exit 1
}

exit 0
