#!/bin/bash

# =============================================================================
# Script:   csc_write_vpn.sh
# Purpose:  Writes the AnyConnect-compatible VPN XML profile to the correct
#           Cisco Secure Client VPN profile directory on macOS endpoints
#           managed through Jamf Pro.
#
# Overview:
#   This script is a targeted configuration deployment script invoked by
#   the Configuration Enforcement Script (csc_config_enforcement.sh) when
#   a hash mismatch or missing file is detected for the VPN XML profile.
#   It uses a heredoc to write the full XML profile content directly to
#   the expected VPN profile directory, ensuring the file is always
#   restored to an exact known-good state regardless of what was
#   previously present at that path.
#
#   The XML profile content is embedded directly within the script and
#   defines all VPN client initialization parameters and server list
#   entries required for Cisco Secure Client to establish a VPN connection
#   to the headend.
#
#   This script is intended to be assigned to a dedicated Jamf Pro policy
#   configured with a custom event trigger that exactly matches the
#   policyEventTrigger value defined in the VPN profile check parameter
#   of the Configuration Enforcement policy. It is called on demand by
#   the enforcement script and should not be assigned a recurring
#   check-in trigger.
#
# Usage:
#   Deployed via Jamf Pro policy. To invoke the associated policy manually
#   on a managed device:
#     sudo jamf policy -event <custom_event_trigger>
#
#   Example:
#     sudo jamf policy -event deploy_vpn_profile
#
# Parameters:
#   None. All configuration values are defined as variables within the
#   script.
#
# Configuration:
#   The following variable and embedded content must be updated to match
#   your environment before deployment:
#
#   xmlfile     - The destination path for the VPN XML profile, including
#                 the profile filename. Defaults to:
#                   /opt/cisco/secureclient/vpn/profile/Cert_Profile.xml
#                 The filename component must be updated to match the
#                 profile filename used in your environment and must be
#                 consistent with the filename defined in the
#                 Configuration Enforcement policy parameter for the VPN
#                 profile check. A mismatch between this filename and the
#                 value defined in the enforcement policy will cause the
#                 enforcement script to be unable to locate the deployed
#                 file for hash validation, resulting in continuous
#                 remediation attempts.
#
#   VPN XML     - The entire XML block between the heredoc delimiters
#   profile       must be replaced with the actual VPN XML profile for
#   content       your organization before this script is deployed.
#                 The placeholder server address (example.vpn.sse.cisco.com)
#                 and all ClientInitialization values must reflect your
#                 organization's actual VPN gateway configuration.
#
#                 IMPORTANT: After finalizing the script content, the
#                 SHA256 hash of the resulting profile file must be
#                 recalculated and updated in the Configuration
#                 Enforcement policy parameter for the VPN profile check.
#                 To calculate the hash, run this script on a test device
#                 and execute:
#                   shasum -a 256 /opt/cisco/secureclient/vpn/profile/ \
#                   <profilename>.xml | awk '{print $1}'
#                 Any subsequent change to the XML content will produce a
#                 different hash and will require this value to be
#                 recalculated and updated in the enforcement policy.
#
# Requirements:
#   - Script must be executed in the root context, as is the case when
#     run via a Jamf Pro policy.
# =============================================================================

xmlfile="/opt/cisco/secureclient/vpn/profile/Cert_Profile.xml"

# Make Simple File
MAKEXML()
{
	echo "Creating SimpleXML"
	cat > "$xmlfile" <<EOF
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
EOF
}

# Main Process
MAKEXML
