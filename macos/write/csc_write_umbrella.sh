#!/bin/bash

# =============================================================================
# Script:   csc_write_umbrella.sh
# Purpose:  Writes the Umbrella OrgInfo.json file to the correct Cisco
#           Secure Client Umbrella module directory on macOS endpoints
#           managed through Jamf Pro.
#
# Overview:
#   This script is a targeted configuration deployment script invoked by
#   the Configuration Enforcement Script (csc_config_enforcement.sh) when
#   a hash mismatch or missing file is detected for the Umbrella
#   OrgInfo.json file. It uses a heredoc to write the JSON content
#   directly to the expected Umbrella module directory, ensuring the file
#   is always restored to an exact known-good state regardless of what
#   was previously present at that path.
#
#   The OrgInfo.json content is embedded directly within the script and
#   contains the organizational credentials required for the Umbrella
#   module to establish DNS-layer security and Secure Web Gateway
#   functionality. Following deployment of this file, the Configuration
#   Enforcement Script will terminate and restart the vpnagentd process
#   to force the Umbrella module to reinitialize with the newly written
#   configuration. This script does not perform that restart itself.
#
#   This script is intended to be assigned to a dedicated Jamf Pro policy
#   configured with a custom event trigger that exactly matches the
#   policyEventTrigger value defined in the Umbrella profile check
#   parameter of the Configuration Enforcement policy. It is called on
#   demand by the enforcement script and should not be assigned a
#   recurring check-in trigger.
#
# Usage:
#   Deployed via Jamf Pro policy. To invoke the associated policy manually
#   on a managed device:
#     sudo jamf policy -event <custom_event_trigger>
#
#   Example:
#     sudo jamf policy -event deploy_umbrella_profile
#
# Parameters:
#   None. All configuration values are defined as variables within the
#   script.
#
# Configuration:
#   The following variable and embedded content must be updated to match
#   your environment before deployment:
#
#   jsonFile    - The destination path for the OrgInfo.json file.
#                 Defaults to:
#                   /opt/cisco/secureclient/umbrella/OrgInfo.json
#                 This path reflects the standard Umbrella module
#                 directory on macOS and should not be modified.
#
#   OrgInfo.json - The JSON block embedded within the heredoc must be
#   content        replaced with the actual Umbrella organizational
#                  credentials for your environment. The placeholder
#                  values for fingerprint, organizationId, and userId
#                  must reflect the values from the OrgInfo.json file
#                  downloaded from the Cisco Secure Access dashboard.
#
#                  IMPORTANT: After finalizing the script content, the
#                  SHA256 hash of the resulting OrgInfo.json file must
#                  be recalculated and updated in the Configuration
#                  Enforcement policy parameter for the Umbrella profile
#                  check. To calculate the hash, run this script on a
#                  test device and execute:
#                    shasum -a 256 /opt/cisco/secureclient/umbrella/ \
#                    OrgInfo.json | awk '{print $1}'
#                  Any subsequent change to the JSON content will produce
#                  a different hash and will require this value to be
#                  recalculated and updated in the enforcement policy.
#
# Requirements:
#   - Script must be executed in the root context, as is the case when
#     run via a Jamf Pro policy.
# =============================================================================

jsonFile="/opt/cisco/secureclient/umbrella/OrgInfo.json"

printf '%s' "$(cat << 'EOF'
{
  "fingerprint": "abcdef1234567890",
  "organizationId": "0000000",
  "region": "global",
  "userId": "00000000"
}
EOF
)" > "${jsonFile}"

