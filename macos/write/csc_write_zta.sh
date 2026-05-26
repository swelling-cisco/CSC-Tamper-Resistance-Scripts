#!/bin/bash

# =============================================================================
# Script:   csc_write_zta.sh
# Purpose:  Creates the ZTA enrollment choices directory if it does not
#           already exist and writes the signed ZTA enrollment JSON file
#           to the correct location on macOS endpoints managed through
#           Jamf Pro.
#
# Overview:
#   This script is a targeted configuration deployment script invoked by
#   the Configuration Enforcement Script (csc_config_enforcement.sh) when
#   a hash mismatch or missing file is detected for the ZTA enrollment
#   JSON file. It creates the enrollment choices directory with the
#   correct permissions if it is not already present, then uses a heredoc
#   to write the signed ZTA enrollment JSON content directly to the target
#   path, ensuring the file is always restored to an exact known-good
#   state regardless of what was previously present at that path.
#
#   The ZTA enrollment JSON content is embedded directly within the
#   script. After writing the file, the script confirms that the file
#   was created successfully and reports the outcome.
#
#   This script is only required when certificate-based ZTA enrollment is
#   in use. If your environment uses SAML-based enrollment, this script
#   is not needed and the associated Configuration Enforcement policy
#   parameter for the ZTA profile check can be left blank.
#
#   This script is intended to be assigned to a dedicated Jamf Pro policy
#   configured with a custom event trigger that exactly matches the
#   policyEventTrigger value defined in the ZTA profile check parameter
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
#     sudo jamf policy -event deploy_zta_profile
#
# Parameters:
#   None. All configuration values are defined as variables within the
#   script.
#
# Configuration:
#   The following variables and embedded content must be updated to match
#   your environment before deployment:
#
#   FILENAME    - The filename of the ZTA enrollment JSON file. Must be
#                 updated to reflect the actual enrollment filename for
#                 your organization, which follows the format:
#                   <OrgID>_ZTA_Enroll_Cert.json
#                 This value must be consistent with the filename defined
#                 in the Configuration Enforcement policy parameter for
#                 the ZTA profile check. The enforcement script uses this
#                 filename to distinguish the expected enrollment file
#                 from any extraneous files present in the enrollment
#                 directory. A mismatch between this filename and the
#                 value defined in the enforcement policy will cause the
#                 enforcement script to be unable to locate the deployed
#                 file for hash validation, resulting in continuous
#                 remediation attempts.
#
#   ZTA          - The JSON block embedded within the heredoc must be
#   enrollment     replaced with the actual ZTA enrollment configuration
#   JSON content   for your organization. The signed_payload field must
#                  contain the valid signed JWT from the ZTA enrollment
#                  configuration file downloaded from the Cisco Secure
#                  Access dashboard under Connect > Essentials > End User
#                  Connectivity > Zero Trust Access > Enrollment Methods.
#                  The placeholder JWT value included in this script is
#                  not a valid enrollment payload and must not be used in
#                  production deployments.
#
#                  IMPORTANT: After finalizing the script content, the
#                  SHA256 hash of the resulting enrollment JSON file must
#                  be recalculated and updated in the Configuration
#                  Enforcement policy parameter for the ZTA profile check.
#                  To calculate the hash, run this script on a test device
#                  and execute:
#                    shasum -a 256 /opt/cisco/secureclient/zta/
#                    enrollment_choices/<OrgID>_ZTA_Enroll_Cert.json \
#                    | awk '{print $1}'
#                  Any subsequent change to the JSON content will produce
#                  a different hash and will require this value to be
#                  recalculated and updated in the enforcement policy.
#
# Requirements:
#   - Script must be executed in the root context, as is the case when
#     run via a Jamf Pro policy.
# =============================================================================

#Make Enrollment choices folder if it does not exist
mkdir -p "/opt/cisco/secureclient/zta/enrollment_choices/"
#Change permissions of folder
chmod 755 "/opt/cisco/secureclient/zta/enrollment_choices"

# Define the filename
FILENAME="OrgID_ZTA_Enroll_Cert.json"

# Define the target directory
TARGET_DIR="/opt/cisco/secureclient/zta/enrollment_choices/"

# Create the full path for the file
FILE_PATH="${TARGET_DIR}/${FILENAME}"

# Write the JSON content to the specified file
printf '%s' "$(cat << 'EOF'
{
    "version": 1,
    "comment": "Auto Enrollment Configuration",
    "signed_payload": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJkdW1teSIsIm5hbWUiOiJleGFtcGxlIiwiaWF0IjoxNzczMzYzMDk1fQ.ZHVtbXlfc2lnbmF0dXJl"
}
EOF
)" > "${FILE_PATH}"

# Provide confirmation
if [ -f "${FILE_PATH}" ]; then
    echo "File '${FILENAME}' successfully created in '${TARGET_DIR}'."
else
    echo "Failed to create file '${FILENAME}' in '${TARGET_DIR}'."
fi
