# =============================================================================
# Script:   vpn_config_remediation.ps1
# Purpose:  Restores the Cisco Secure Client AnyConnect VPN connection profile
#           to its authoritative baseline state on Windows endpoints when
#           configuration drift is detected. Used by Microsoft Intune as the
#           remediation script in the VPN Configuration remediation script pair.
#
# Overview:
#   This script restores the VPN XML profile by performing the following steps:
#
#     1. Removes the existing VPN XML profile from the Cisco Secure Client
#        VPN profile directory if it is present, ensuring a clean write.
#     2. Creates the VPN profile directory if it does not already exist.
#     3. Writes the authoritative VPN XML profile content to the correct
#        path using UTF-8 encoding without BOM and LF line endings, ensuring
#        that the resulting file produces a consistent and predictable SHA-256
#        hash that matches the value configured in the paired detection script.
#
#   This script is executed by Intune only when the paired
#   vpn_config_detection.ps1 script exits with code 1, indicating that the
#   VPN profile is either absent or does not match the expected baseline hash.
#
# Usage:
#   Uploaded as the remediation script of the VPN Configuration remediation
#   script pair in the Intune Remediations console. Can also be tested
#   locally using PsExec in the SYSTEM account context:
#   ./PsExec.exe -i -s powershell.exe -ExecutionPolicy Bypass -File "vpn_config_remediation.ps1"; $LASTEXITCODE
#
# Configuration:
#   - Update $XMLFileName to match the filename of the VPN XML profile used
#     in your environment. This value must match the filename configured in
#     the paired vpn_config_detection.ps1 script.
#     Example: "Cert_Profile.xml"
#   - Update the $XMLContent heredoc block with the complete and authoritative
#     XML content of the VPN profile for your environment. The file content
#     must be placed between the @' and '@ delimiters exactly as it should
#     appear on disk. Do not add or remove whitespace, line breaks, or
#     characters outside of those delimiters, as any change to the content
#     will alter the SHA-256 hash of the written file and cause the paired
#     detection script to continuously report a mismatch.
#   - After finalizing the $XMLContent block, recalculate the expected SHA-256
#     hash by deploying this remediation script to a test device and running
#     the following command in PowerShell to obtain the hash of the written
#     file:
#
#       (Get-FileHash -Path "C:\ProgramData\Cisco\Cisco Secure Client\VPN\Profile\Cert_Profile.xml" -Algorithm SHA256).Hash
#
#     Enter the resulting value as the $ExpectedHash in the paired
#     vpn_config_detection.ps1 script. If the $XMLContent block is updated
#     in the future, this process must be repeated and the $ExpectedHash
#     value must be updated accordingly.
#   - $VPNProfileFolder defines the directory where the VPN XML profile will
#     be written. This value should not be changed.
#
# Exit Codes:
#   0 — The VPN XML profile has been successfully written to the expected
#       path and confirmed as present on disk. Intune will record the
#       remediation as successful.
#   1 — The VPN XML profile was not found on disk after the write operation
#       completed, indicating that the remediation did not succeed. Intune
#       will record the remediation as failed and retry on the next cycle.
# =============================================================================

[CmdletBinding()]
param ()

# Defines the target directory and file path for the VPN connection profile
$VPNProfileFolder = "C:\ProgramData\Cisco\Cisco Secure Client\VPN\Profile"
$XMLFileName      = "Cert_Profile.xml"
$XMLFilePath      = Join-Path -Path $VPNProfileFolder -ChildPath $XMLFileName

# Defines the authoritative VPN profile XML content to be written during remediation
$XMLContent = @'
<?xml version="1.0" encoding="UTF-8"?>
<AnyConnectProfile xmlns="http://schemas.xmlsoap.org/encoding/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://schemas.xmlsoap.org/encoding/ AnyConnectProfile.xsd">
	<ClientInitialization>
		<CertificatePinning>false</CertificatePinning>
		<UseStartBeforeLogon UserControllable="true">true</UseStartBeforeLogon>
		<WindowsLogonEnforcement>SingleLocalLogon</WindowsLogonEnforcement>
		<WindowsVPNEstablishment>LocalUsersOnly</WindowsVPNEstablishment>
		<LinuxLogonEnforcement>SingleLocalLogon</LinuxLogonEnforcement>
		<LinuxVPNEstablishment>LocalUsersOnly</LinuxVPNEstablishment>
		<CertificateStore>All</CertificateStore>
		<CertificateStoreMac>All</CertificateStoreMac>
		<CertificateStoreLinux>All</CertificateStoreLinux>
		<CertificateStoreOverride>false</CertificateStoreOverride>
		<LocalLanAccess UserControllable="false">false</LocalLanAccess>
		<AutoReconnect UserControllable="true">true
			<AutoReconnectBehavior UserControllable="false">ReconnectAfterResume</AutoReconnectBehavior>
		</AutoReconnect>
		<MinimizeOnConnect UserControllable="true">true</MinimizeOnConnect>
		<SuspendOnConnectedStandby>false</SuspendOnConnectedStandby>
		<ClearSmartcardPin UserControllable="false">true</ClearSmartcardPin>
		<IPProtocolSupport>IPv4</IPProtocolSupport>
		<AutomaticCertSelection UserControllable="false">true</AutomaticCertSelection>
		<AllowLocalProxyConnections>true</AllowLocalProxyConnections>
		<EnableAutomaticServerSelection UserControllable="false">false</EnableAutomaticServerSelection>
		<ProxySettings>Native</ProxySettings>
		<AutomaticVPNPolicy>false</AutomaticVPNPolicy>
		<CaptivePortalRemediationBrowserFailover>false</CaptivePortalRemediationBrowserFailover>
		<AuthenticationTimeout>30</AuthenticationTimeout>
		<AllowManualHostInput>true</AllowManualHostInput>
	</ClientInitialization>
	<ServerList>
		<HostEntry>
			<HostName>Certificate - TLS - Auto Select Nearest Location</HostName>
			<HostAddress>example.vpn.sse.cisco.com</HostAddress>
			<UserGroup>Cert</UserGroup>
			<LoadBalancingServerList>
				<HostAddress>*-example.vpn.sse.cisco.com</HostAddress>
			</LoadBalancingServerList>
		</HostEntry>
	</ServerList>
</AnyConnectProfile>

'@

# Removes the existing VPN profile file if present, suppressing errors if it does not exist
function Remove-VPNProfile {
    [CmdletBinding()]
    param ()

    if (Test-Path $XMLFilePath) {
        try {
            Remove-Item -Path $XMLFilePath -Force -ErrorAction Stop
            Write-Verbose "Removed $XMLFileName"
        } catch {
            Write-Verbose "Failed to remove $XMLFileName : $_"
        }
    } else {
        Write-Verbose "$XMLFileName does not exist, skipping removal"
    }
}

# Creates the profile directory if absent, then writes the authoritative XML content
# using UTF-8 encoding without BOM and LF line endings to ensure hash consistency
function Write-VPNProfile {
    [CmdletBinding()]
    param ()

    if (-not (Test-Path $VPNProfileFolder)) {
        New-Item -ItemType Directory -Path $VPNProfileFolder -Force | Out-Null
        Write-Verbose "Created VPN Profile folder"
    }

    try {
        $LFContent = $XMLContent -replace "`r`n", "`n"
        $UTF8NoBOM = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($XMLFilePath, $LFContent, $UTF8NoBOM)
        Write-Verbose "Wrote $XMLFileName (UTF-8 no BOM, LF line endings)"
    } catch {
        Write-Verbose "Failed to write $XMLFileName : $_"
    }
}

# Initializes the remediation result object with default values prior to execution
$RemediationResult = [PSCustomObject]@{
    FileRemoved  = $false
    FileWritten  = $false
    FileExists   = $false
}

# Removes the existing profile and confirms deletion before proceeding
Remove-VPNProfile
$RemediationResult.FileRemoved = -not (Test-Path $XMLFilePath)

# Writes the authoritative profile and confirms the file is present on disk
Write-VPNProfile
$RemediationResult.FileWritten = Test-Path $XMLFilePath
$RemediationResult.FileExists  = Test-Path $XMLFilePath

# Returns exit code 0 if the remediated file is confirmed present, otherwise exit code 1
if ($RemediationResult.FileExists) { Exit 0 } else { Exit 1 }
