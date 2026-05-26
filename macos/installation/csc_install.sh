#!/bin/bash

# =============================================================================
# Script:   csc_install.sh
# Purpose:  Installs the Cisco Secure Client package on macOS endpoints
#           managed through Jamf Pro, applying a pre-generated choices file
#           to control which modules are installed.
#
# Overview:
#   This script performs the Cisco Secure Client package installation by
#   invoking the macOS installer command with the -applyChoiceChangesXML
#   flag, which instructs the installer to use the module selections defined
#   in the install_choices.xml file rather than the package defaults. This
#   ensures that only the modules specified in the choices file are installed,
#   both during initial deployment and during enforcement-triggered
#   reinstallation.
#
#   The script references a cached copy of the Cisco Secure Client .pkg file
#   from the Jamf Pro Waiting Room, which is the local on-disk directory
#   where Jamf Pro stores packages downloaded to the endpoint.
#
#   On execution, the script invokes the installer binary with the package
#   path, a target of the root volume, and the choices file path. It
#   validates the exit code of the installer and reports success or failure
#   accordingly.
#
#   This script is intended to be configured as the After script in the Jamf
#   Pro installation policy referenced by the Module Enforcement Script
#   (csc_module_enforcement.sh) and the Orchestrator Script
#   (csc_enforcement_orchestrator.sh) as the Tier 3 remediation target. The
#   Install Choices Script (csc_choices.sh) must be configured as the Before
#   script in the same policy and must execute successfully before this
#   script runs to ensure the choices file is present at the expected path
#   when the installer is invoked.
#
# Usage:
#   Deployed via Jamf Pro policy as the After script. To invoke the
#   associated policy manually on a managed device:
#     sudo jamf policy -event <custom_event_trigger>
#
#   Example:
#     sudo jamf policy -event csc_install
#
# Parameters:
#   None. All configuration values are defined as variables within the
#   script.
#
# Configuration:
#   The following variables must be reviewed and updated to match your
#   environment before deployment:
#
#   choicesDir  - The directory in which the install_choices.xml file is
#                 written by the Install Choices Script. Defaults to:
#                   /Library/Application Support/SecureClientEnforcement
#                 This path is consistent with the shared state directory
#                 used by the broader enforcement framework. This value
#                 should only be changed if your environment requires a
#                 different path, and must be updated consistently in both
#                 this script and csc_choices.sh if changed.
#
#   choicesFile - The full path to the install_choices.xml file. Derived
#                 from choicesDir and the fixed filename
#                 install_choices.xml. Must exactly match the path used in
#                 csc_choices.sh. If the choices file is absent at this
#                 path when the installer runs, the installation will
#                 proceed using the package defaults, potentially installing
#                 modules that were intended to be excluded.
#
#   pkgPath     - The full path to the Cisco Secure Client .pkg file in the
#                 Jamf Pro Waiting Room on the endpoint. Defaults to:
#                   /Library/Application Support/JAMF/Waiting Room/
#                   Cisco Secure Client.pkg
#                 The filename component of this path must match the
#                 filename of the package as it appears in Jamf Pro, which
#                 is the filename of the uploaded .pkg file and may differ
#                 from the Display Name configured in the package record.
#                 If the package was uploaded to Jamf Pro with a different
#                 filename, this path must be updated accordingly before
#                 deployment.
#
# Requirements:
#   - csc_choices.sh must be configured as the Before script in the same
#     Jamf Pro policy and must complete successfully before this script
#     runs, ensuring the install_choices.xml file is present at the path
#     defined in choicesFile.
#   - The Cisco Secure Client .pkg file must be present in the Jamf Pro
#     Waiting Room at the path defined in pkgPath. This is handled
#     automatically by configuring the package action as Cache in the
#     Jamf Pro policy.
#   - Script must be executed in the root context, as is the case when
#     run via a Jamf Pro policy.
# =============================================================================

choicesDir="/Library/Application Support/SecureClientEnforcement"
choicesFile="${choicesDir}/install_choices.xml"
pkgPath="/Library/Application Support/JAMF/Waiting Room/Cisco Secure Client.pkg"


# Install Package with Choices File Applied
INSTALLPKG()
{
    echo "Installing Cisco Secure Client with choices file: $choicesFile"
    installer -pkg "$pkgPath" \
              -target "/" \
              -applyChoiceChangesXML "$choicesFile"

    if [ $? -ne 0 ]; then
        echo "ERROR: Installation failed."
        exit 1
    else
        echo "Installation completed successfully."
    fi
}

INSTALLPKG
