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
