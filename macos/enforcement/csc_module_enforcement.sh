#!/bin/bash

# =============================================================================
# Script:   csc_module_enforcement.sh
# Purpose:  Validates the health and integrity of the Cisco Secure Client
#           installation on macOS endpoints managed through Jamf Pro, and
#           remediates detected issues using a tiered escalation approach.
#
# Overview:
#   This script performs a tiered series of checks against the Cisco Secure
#   Client installation and responds with the least disruptive remediation
#   available before escalating to more impactful approaches.
#
#   On each execution, the script follows this sequence:
#     1. Checks whether the VPN is currently connected. If connected, records
#        the compliance issue and increments the deferral counter in the
#        shared state file, then exits without remediating. The orchestrator
#        is responsible for managing the user prompt and VPN disconnect when
#        the deferral threshold is reached.
#     2. Reads the CFBundleShortVersionString from the Cisco Secure Client
#        application Info.plist and compares it hierarchically against the
#        minimum version configured in Parameter $4. If the installed version
#        is below the minimum, a Tier 3 full uninstall and reinstall is
#        flagged.
#     3. Verifies that each launch daemon defined in the scLaunchDaemons
#        array is in a running state using launchctl print.
#     4. Verifies that each binary defined in the scBinaries array is present
#        on disk and active as a running process using pgrep.
#     5. Verifies that each critical plist file defined in the scFiles array
#        is present on disk.
#
#   Remediation is tiered based on the nature and severity of the detected
#   issue:
#
#     Tier 1 – Stopped launch daemons:
#       Attempts a targeted restart using launchctl kickstart if the daemon
#       is already registered with launchd, or launchctl enable followed by
#       launchctl bootstrap for daemons that are not yet registered.
#
#     Tier 2 – Non-running binaries:
#       Attempts to deploy any missing configuration files required by the
#       affected module via the relevant Jamf Pro configuration policy before
#       restarting the associated launch daemons.
#
#     Tier 3 – Missing files, version mismatch, or failed lower-tier
#       remediation:
#       Performs a full uninstall using the Cisco-provided uninstall script,
#       removes all package receipts, cleans up residual installation
#       directories, and triggers the Jamf Pro installer policy to perform
#       a clean reinstallation. Configuration deployment policies for VPN,
#       Umbrella, and ZTA are triggered prior to reinstallation to ensure
#       configuration files are staged before the installer runs.
#
#   Compliance state, deferral counts, and first-detection timestamps are
#   written to a shared plist file after each execution for use by the
#   Orchestrator Script (csc_enforcement_orchestrator.sh).
#
#   This script is intended to be assigned to a Jamf Pro policy configured
#   with a custom event trigger and called by the orchestrator during each
#   enforcement cycle.
#
# Usage:
#   Deployed via Jamf Pro policy. To invoke manually on a managed device:
#     sudo jamf policy -event <custom_event_trigger>
#
#   Example:
#     sudo jamf policy -event csc_enforce_modules
#
# Parameters (configured in the Jamf Pro policy):
#   $4 - Minimum Version             The minimum acceptable version of Cisco
#        (e.g., 5.1.15.1561)         Secure Client. Must be provided as a
#                                    4-part version string in the format
#                                    Major.Minor.BuildMajor.BuildMinor.
#                                    The script evaluates this against the
#                                    CFBundleShortVersionString read from the
#                                    Cisco Secure Client GUI application
#                                    bundle, which may differ from the version
#                                    number of the individual module installer
#                                    packages. Before configuring this value,
#                                    verify the exact version string reported
#                                    on a device with the target version
#                                    installed by running:
#                                      defaults read "/Applications/Cisco/
#                                      Cisco Secure Client.app/Contents/
#                                      Info.plist"
#                                      CFBundleShortVersionString
#   $5 - CSC Installer Policy Event  Custom event trigger for the Jamf Pro
#                                    policy that installs or reinstalls Cisco
#                                    Secure Client (e.g., csc_install).
#   $6 - VPN Profile Policy Event    Custom event trigger for the Jamf Pro
#                                    policy that deploys the VPN XML profile
#                                    (e.g., deploy_vpn_profile).
#   $7 - Umbrella JSON Policy Event  Custom event trigger for the Jamf Pro
#                                    policy that deploys the Umbrella
#                                    OrgInfo.json file
#                                    (e.g., deploy_umbrella_profile).
#   $8 - ZTA Enrollment JSON Policy  Custom event trigger for the Jamf Pro
#        Event                       policy that deploys the ZTA enrollment
#                                    JSON file (e.g., deploy_zta_profile).
#
# Configuration:
#   The following variables can be adjusted to suit your environment:
#
#   STATE_FILE    - Full path to the shared plist file used to record
#                   compliance state, deferral counts, and first-detection
#                   timestamps for this script's policy identifier.
#                   Default:
#                     /Library/Application Support/
#                     SecureClientEnforcement/
#                     csc_enforcement_state.plist
#                   IMPORTANT: This value must be identical across
#                   csc_enforcement_orchestrator.sh,
#                   csc_module_enforcement.sh, and
#                   csc_config_enforcement.sh. A path mismatch between
#                   any of these scripts will prevent the orchestrator
#                   from reading compliance state written by this script,
#                   causing compliance issues detected by the module
#                   enforcement checks to be invisible to the coordination
#                   layer and preventing the orchestrator from triggering
#                   the appropriate remediation response.
#
#   scLaunchDaemons array
#               - Defines the launch daemons verified by the script.
#                   The default entries cover the VPN service agent and
#                   ZTA app agent. Add or remove entries to match the
#                   modules deployed in your environment.
#
#   scBinaries array
#               - Defines the binary executables verified by the script.
#                   The default entries cover the SWG agent, Umbrella
#                   agent, VPN agent daemon, and ZTA agent.
#                   NOTE: This script assumes that both the DNS and SWG
#                   features are enabled within the Cisco Secure Access
#                   organization. When only DNS is enabled and SWG is not,
#                   the csc_swgagent binary has been observed to remain
#                   disabled on macOS devices. If SWG is not enabled in
#                   your environment, the csc_swgagent entry must be
#                   commented out or removed from this array. Leaving it
#                   in place when SWG is not enabled will cause the script
#                   to continuously detect csc_swgagent as not running and
#                   trigger a full uninstall and reinstallation of Cisco
#                   Secure Client on every enforcement cycle.
#
#   scFiles array
#               - Defines the critical plist files verified by the script.
#                   The default entries cover the VPN service agent plist
#                   and ZTA app agent plist. Add or remove entries to
#                   match the modules deployed in your environment.
#
# Requirements:
#   - The Jamf Pro policies referenced in Parameters $5 through $8 must
#     be configured with matching custom event trigger names before this
#     script is deployed.
#   - The Cisco Secure Client uninstall script must be present at:
#       /opt/cisco/secureclient/bin/cisco_secure_client_uninstall.sh
#     for Tier 3 remediation to complete successfully.
#   - The Cisco Secure Client VPN binary must be present at:
#       /opt/cisco/secureclient/bin/vpn
#     for VPN connection state detection.
#   - Script must be executed in the root context, as is the case when
#     run via a Jamf Pro policy.
# =============================================================================

# Parse minimum version string from parameter 4
scMinVersionString="$4"
# Parse version components from the minimum version string
scMinVersionMajor=$(echo "$scMinVersionString" | awk 'BEGIN { FS = "." } ; {print $1}')
scMinVersionMinor=$(echo "$scMinVersionString" | awk 'BEGIN { FS = "." } ; {print $2}')
scMinVersionBuildMajor=$(echo "$scMinVersionString" | awk 'BEGIN { FS = "." } ; {print $3}' | sed 's/^0*//')
scMinVersionBuildMinor=$(echo "$scMinVersionString" | awk 'BEGIN { FS = "." } ; {print $4}' | sed 's/^0*//')

# Parse Jamf policy event triggers from parameters 5, 6, and 7
cscInstallerPolicy="$5"  # Main CSC installer policy
csaProfilePolicy="$6"    # Cisco Secure Access profile policy
swgJSONPolicy="$7"       # Secure Web Gateway JSON policy
ztaJSONPolicy="$8"       # Zero Trust Access JSON policy

# Path to Cisco Secure Client main application Info.plist
scPath="/Applications/Cisco/Cisco Secure Client.app/Contents/Info.plist"

# Counter for policy violations - incremented when issues are found
runPolicy=0

# Array of launch daemons to monitor (system-level services)
scLaunchDaemons=(
'com.cisco.secureclient.vpn.service.agent'
'com.cisco.secureclient.zta.app.agent'
)

# Array of binary executables to verify are installed and running
scBinaries=(
'/opt/cisco/secureclient/bin/csc_swgagent'
'/opt/cisco/secureclient/bin/acumbrellaagent'
'/opt/cisco/secureclient/bin/Cisco Secure Client - AnyConnect VPN Service.app/Contents/MacOS/vpnagentd'
'/opt/cisco/secureclient/zta/bin/Cisco Secure Client - Zero Trust Access.app/Contents/MacOS/csc_zta_agent'
)

# Array of critical plist files required for launch daemons
scFiles=(
  '/opt/cisco/secureclient/bin/Cisco Secure Client - AnyConnect VPN Service.app/Contents/Library/LaunchDaemons/com.cisco.secureclient.vpn.service.agent.plist'
  '/opt/cisco/secureclient/zta/bin/Cisco Secure Client - Zero Trust Access.app/Contents/Library/LaunchDaemons/com.cisco.secureclient.zta.app.agent.plist'
)

#########################
# Embedded State Management
# Include this block in each script that needs state tracking
#########################
STATE_FILE="/Library/Application Support/SecureClientEnforcement/csc_enforcement_state.plist"
POLICY_ID="csc_enforcement"  # Used by orchestrator to identify this policy type

current_event_override=$(/usr/libexec/PlistBuddy -c "Print :global:current_event" "$STATE_FILE" 2>/dev/null)
if [[ -n "$current_event_override" ]]; then
  if [[ "$current_event_override" =~ ^[A-Za-z0-9._-]+$ ]]; then
    POLICY_ID="$current_event_override"
  else
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] WARNING: Ignoring invalid POLICY_ID override (unsafe characters): ${current_event_override}" >&2
  fi
fi

# Configurable thresholds
DEFERRAL_THRESHOLD=3
MAX_DEFERRAL_HOURS=4

init_state_file() {
    local dir
    dir=$(dirname "$STATE_FILE")
    [[ ! -d "$dir" ]] && mkdir -p "$dir"
    if [[ ! -f "$STATE_FILE" ]]; then
        /usr/libexec/PlistBuddy -c "Save" "$STATE_FILE" 2>/dev/null
        log_message "Created new state file"
    fi
}

log_message() {
    local msg="$1"
    /usr/bin/logger -t "[CSC-Enforce]" "${POLICY_ID}: ${msg}"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [${POLICY_ID}] ${msg}"
}

writeLog() {
  log_message "$1"
}

record_needs_action() {
    local reason="$1"
    init_state_file
    local now
    now=$(date +%s)
    
    # Check if entry already exists (preserve first_detected time and deferral count)
    local existing_time existing_count
    existing_time=$(/usr/libexec/PlistBuddy -c "Print :${POLICY_ID}:first_detected" "$STATE_FILE" 2>/dev/null)
    existing_count=$(/usr/libexec/PlistBuddy -c "Print :${POLICY_ID}:deferred_count" "$STATE_FILE" 2>/dev/null || echo 0)
    
    /usr/libexec/PlistBuddy -c "Delete :${POLICY_ID}" "$STATE_FILE" 2>/dev/null
    /usr/libexec/PlistBuddy -c "Add :${POLICY_ID} dict" "$STATE_FILE"
    /usr/libexec/PlistBuddy -c "Add :${POLICY_ID}:needs_action bool true" "$STATE_FILE"
    /usr/libexec/PlistBuddy -c "Add :${POLICY_ID}:reason string '${reason}'" "$STATE_FILE"
    
    # Preserve original detection time if it existed
    if [[ -n "$existing_time" && "$existing_time" != "" ]]; then
        /usr/libexec/PlistBuddy -c "Add :${POLICY_ID}:first_detected integer ${existing_time}" "$STATE_FILE"
    else
        /usr/libexec/PlistBuddy -c "Add :${POLICY_ID}:first_detected integer ${now}" "$STATE_FILE"
    fi
    
    # Preserve existing deferral count
    /usr/libexec/PlistBuddy -c "Add :${POLICY_ID}:deferred_count integer ${existing_count}" "$STATE_FILE" 2>/dev/null
    
    log_message "Recorded needs_action: ${reason} (preserved deferral_count: ${existing_count})"
}

increment_deferral() {
    init_state_file
    local count
    count=$(/usr/libexec/PlistBuddy -c "Print :${POLICY_ID}:deferred_count" "$STATE_FILE" 2>/dev/null || echo 0)
    ((count++))
    /usr/libexec/PlistBuddy -c "Set :${POLICY_ID}:deferred_count ${count}" "$STATE_FILE" 2>/dev/null || \
        /usr/libexec/PlistBuddy -c "Add :${POLICY_ID}:deferred_count integer ${count}" "$STATE_FILE"
    log_message "Incremented deferral count to ${count} (VPN connected)"
    echo "$count"
}

get_deferral_count() {
    /usr/libexec/PlistBuddy -c "Print :${POLICY_ID}:deferred_count" "$STATE_FILE" 2>/dev/null || echo 0
}

clear_state() {
    init_state_file
    if ! /usr/libexec/PlistBuddy -c "Print :${POLICY_ID}" "$STATE_FILE" &>/dev/null; then
        /usr/libexec/PlistBuddy -c "Add :${POLICY_ID} dict" "$STATE_FILE" 2>/dev/null
    fi
    /usr/libexec/PlistBuddy -c "Set :${POLICY_ID}:needs_action false" "$STATE_FILE" 2>/dev/null || \
        /usr/libexec/PlistBuddy -c "Add :${POLICY_ID}:needs_action bool false" "$STATE_FILE" 2>/dev/null
    /usr/libexec/PlistBuddy -c "Set :${POLICY_ID}:reason 'Healthy - All checks passed'" "$STATE_FILE" 2>/dev/null || \
        /usr/libexec/PlistBuddy -c "Add :${POLICY_ID}:reason string 'Healthy - All checks passed'" "$STATE_FILE" 2>/dev/null
    /usr/libexec/PlistBuddy -c "Set :${POLICY_ID}:deferred_count 0" "$STATE_FILE" 2>/dev/null || \
        /usr/libexec/PlistBuddy -c "Add :${POLICY_ID}:deferred_count integer 0" "$STATE_FILE" 2>/dev/null
    /usr/libexec/PlistBuddy -c "Set :${POLICY_ID}:first_detected 0" "$STATE_FILE" 2>/dev/null || \
        /usr/libexec/PlistBuddy -c "Add :${POLICY_ID}:first_detected integer 0" "$STATE_FILE" 2>/dev/null
    local now_ts
    now_ts="$(date +%s)"
    /usr/libexec/PlistBuddy -c "Set :${POLICY_ID}:last_checked ${now_ts}" "$STATE_FILE" 2>/dev/null || \
        /usr/libexec/PlistBuddy -c "Add :${POLICY_ID}:last_checked integer ${now_ts}" "$STATE_FILE" 2>/dev/null
    log_message "Cleared state entry (no longer needs action)"
}

get_first_detected() {
    /usr/libexec/PlistBuddy -c "Print :${POLICY_ID}:first_detected" "$STATE_FILE" 2>/dev/null || echo 0
}

hours_since_first_detected() {
    local first_detected
    first_detected=$(get_first_detected)
    if [[ "$first_detected" -eq 0 ]]; then
        echo 0
        return
    fi
    local now
    now=$(date +%s)
    local diff=$((now - first_detected))
    local hours=$((diff / 3600))
    echo "$hours"
}

should_prompt_user() {
    local count
    count=$(get_deferral_count)
    local hours
    hours=$(hours_since_first_detected)
    
    if [[ "$count" -ge "$DEFERRAL_THRESHOLD" ]] || [[ "$hours" -ge "$MAX_DEFERRAL_HOURS" ]]; then
        return 0  # true - should prompt
    fi
    return 1  # false - don't prompt yet
}
#########################
# End State Management
#########################

# Check if VPN is currently connected - exit script if connected to avoid disruption
# Uses native grep -q for efficient boolean checking without counting
# If VPN binary is missing, sets runPolicy to trigger remediation but allows remediation to proceed
# Returns: 0 if not connected or binary missing (can proceed), 1 if connected (should defer)
scConnectedCheck() {
  local vpnBinary="/opt/cisco/secureclient/bin/vpn"
  
  # Check if VPN binary exists before attempting to query it
  if [[ ! -x "$vpnBinary" ]]; then
    writeLog "Error: VPN binary not found or not executable at $vpnBinary"
    (( runPolicy++ ))
    runPolicyReason=notInstalled
    reasonArray+=("VPN binary missing or not executable")
    return 0  # Return 0 to allow remediation when binary is missing
  fi
  
  # Use grep -q for efficient boolean check (no need to count)
  if "$vpnBinary" state 2>/dev/null | grep -q "state: Connected"; then
    writeLog "VPN is connected - will defer remediation after compliance checks..."
    return 1  # Return 1 to indicate VPN is connected (blocks remediation)
  else
    writeLog "VPN is NOT connected. Continuing..."
    return 0  # Return 0 to indicate VPN is not connected (can proceed with remediation)
  fi
}

# Compare installed Cisco Secure Client version against minimum required version
# Checks Major.Minor.BuildMajor.BuildMinor in hierarchical order
# Uses local variables to avoid global namespace pollution
# Sets runPolicyReason=versionMismatch and increments runPolicy if outdated
# Returns: 0 if version check passes, 1 if version is outdated
scVersionTest() {
  # Check if the Info.plist file exists
  if [[ ! -f "$scPath" ]]; then
    writeLog "Error: Cisco Secure Client Info.plist not found at $scPath"
    (( runPolicy++ ))
    runPolicyReason=notInstalled
    reasonArray+=("Secure Client application not found")
    return 1
  fi
  
  # Read installed version once and parse components
  local installedVersion
  installedVersion=$(defaults read "$scPath" CFBundleShortVersionString 2>/dev/null)
  
  if [[ -z "$installedVersion" ]]; then
    writeLog "Error: Could not read version from $scPath"
    (( runPolicy++ ))
    runPolicyReason=versionMismatch
    reasonArray+=("Unable to determine installed version")
    return 1
  fi
  
  # Parse installed version components using IFS for cleaner splitting
  local scVersionMajor scVersionMinor scVersionBuildMajor scVersionBuildMinor
  IFS='.' read -r scVersionMajor scVersionMinor scVersionBuildMajor scVersionBuildMinor <<< "$installedVersion"
  
  # Remove leading zeros from build numbers
  scVersionBuildMajor=${scVersionBuildMajor#"${scVersionBuildMajor%%[!0]*}"}
  scVersionBuildMinor=${scVersionBuildMinor#"${scVersionBuildMinor%%[!0]*}"}
  
  # Default to 0 if any component is empty
  scVersionMajor=${scVersionMajor:-0}
  scVersionMinor=${scVersionMinor:-0}
  scVersionBuildMajor=${scVersionBuildMajor:-0}
  scVersionBuildMinor=${scVersionBuildMinor:-0}

  writeLog "Installed version: $installedVersion"
  writeLog "Required version: ${scMinVersionMajor}.${scMinVersionMinor}.${scMinVersionBuildMajor}.${scMinVersionBuildMinor}"
  
  # Compare version components hierarchically
  if [[ $scVersionMajor -lt $scMinVersionMajor ]]; then
    (( runPolicy++ ))
    runPolicyReason=versionMismatch
    reasonArray+=("Version mismatch: $installedVersion < ${scMinVersionMajor}.${scMinVersionMinor}.${scMinVersionBuildMajor}.${scMinVersionBuildMinor}")
    return 1
  elif [[ $scVersionMajor -eq $scMinVersionMajor ]]; then
    # Major versions match, check minor
    if [[ $scVersionMinor -lt $scMinVersionMinor ]]; then
      (( runPolicy++ ))
      runPolicyReason=versionMismatch
      reasonArray+=("Version mismatch: $installedVersion < ${scMinVersionMajor}.${scMinVersionMinor}.${scMinVersionBuildMajor}.${scMinVersionBuildMinor}")
      return 1
    elif [[ $scVersionMinor -eq $scMinVersionMinor ]]; then
      # Minor versions match, check build major
      if [[ $scVersionBuildMajor -lt $scMinVersionBuildMajor ]]; then
        (( runPolicy++ ))
        runPolicyReason=versionMismatch
        reasonArray+=("Version mismatch: $installedVersion < ${scMinVersionMajor}.${scMinVersionMinor}.${scMinVersionBuildMajor}.${scMinVersionBuildMinor}")
        return 1
      elif [[ $scVersionBuildMajor -eq $scMinVersionBuildMajor ]]; then
        # Build major versions match, check build minor
        if [[ $scVersionBuildMinor -lt $scMinVersionBuildMinor ]]; then
          (( runPolicy++ ))
          runPolicyReason=versionMismatch
          reasonArray+=("Version mismatch: $installedVersion < ${scMinVersionMajor}.${scMinVersionMinor}.${scMinVersionBuildMajor}.${scMinVersionBuildMinor}")
          return 1
        fi
      fi
    fi
  fi
  
  writeLog "Secure Client is up to date. Checking services..."
  # Note: Don't clear state here - wait until all checks complete
  return 0
}

# Check if all required launch daemons are loaded and running
# Uses launchctl print to verify daemon state
# Sets runPolicyReason=launchdaemonNotRunning and increments runPolicy if any daemon is not running
scLaunchDaemonsCheck()
{
  local notRunningDaemons=()
  
  for EachDaemon in "${scLaunchDaemons[@]}"; do
    # Use launchctl print with proper error handling
    if launchctl print "system/$EachDaemon" 2>/dev/null | grep -q "state = running"; then
      writeLog "$EachDaemon is running..."
    else
      writeLog "$EachDaemon is not running..."
      notRunningDaemons+=("$EachDaemon")
    fi
  done
  
  if [[ ${#notRunningDaemons[@]} -gt 0 ]]; then
    (( runPolicy++ ))
    runPolicyReason=launchdaemonNotRunning
    reasonArray+=("Launch daemons not running: ${notRunningDaemons[*]}")
  else
    # Note: Don't clear state here - wait until all checks complete
    writeLog "All launch daemons are running"
  fi
}

# Check if all required binaries exist and are running as active processes
# Uses pgrep to verify each binary is running
# Sets runPolicyReason=notInstalled if binaries are missing
# Sets runPolicyReason=binaryNotRunning if binaries exist but aren't running
# Populates notRunningBinariesArray for use in remediation
# Increments runPolicy for each issue type found
scBinariesCheck()
{
  local scBinariesInstalled=0
  local missingBinaries=()
  notRunningBinariesArray=()  # Global array for remediation
  
  for EachBinary in "${scBinaries[@]}"; do
    local binaryName
    binaryName="$(basename "$EachBinary")"
    
    if [[ -e "$EachBinary" ]]; then
      (( scBinariesInstalled++ ))
      writeLog "$binaryName found"
      
      # Check if the binary is running as an active process
      if ! pgrep -f "$binaryName" > /dev/null 2>&1; then
        writeLog "$binaryName is not running"
        notRunningBinariesArray+=("$binaryName")
      else
        writeLog "$binaryName is running"
      fi
    else
      missingBinaries+=("$binaryName")
    fi
  done

  if [[ $scBinariesInstalled -lt ${#scBinaries[@]} ]]; then
    (( runPolicy++ ))
    runPolicyReason=notInstalled
    if [[ ${#missingBinaries[@]} -gt 0 ]]; then
      reasonArray+=("Secure Client binaries missing: ${missingBinaries[*]}")
    else
      reasonArray+=("Secure Client binaries missing...")
    fi
  else
    writeLog "Secure Client binaries installed..."
  fi
  
  if [[ ${#notRunningBinariesArray[@]} -gt 0 ]]; then
    (( runPolicy++ ))
    runPolicyReason=binaryNotRunning
    reasonArray+=("Secure Client binaries not running: ${notRunningBinariesArray[*]}")
  else
    # Only clear state if binaries are also installed (checked above)
    if [[ $scBinariesInstalled -eq ${#scBinaries[@]} ]]; then
      # Note: Don't clear state here - wait until all checks complete
      writeLog "All binaries are installed and running"
    fi
  fi
}

# Check if all required plist files exist
# Sets runPolicyReason=notInstalled and increments runPolicy if any files are missing
scFilesCheck()
{
  local scFilesInstalled=0
  local missingFiles=()
  
  for EachFile in "${scFiles[@]}"; do
    if [[ -e "$EachFile" ]]; then
      (( scFilesInstalled++ ))
      writeLog "$(basename "$EachFile") found"
    else
      missingFiles+=("$(basename "$EachFile")")
    fi
  done

  if [[ $scFilesInstalled -lt ${#scFiles[@]} ]]; then
    (( runPolicy++ ))
    runPolicyReason=notInstalled
    if [[ ${#missingFiles[@]} -gt 0 ]]; then
      reasonArray+=("Secure Client files missing: ${missingFiles[*]}")
    else
      reasonArray+=("Secure Client files missing...")
    fi
  else
    writeLog "Secure Client files installed..."
    # Note: Don't clear state here - wait until all checks complete
  fi
}

# Attempt to remediate non-running launch daemons
# Args: array of daemon names to remediate (e.g., com.cisco.secureclient.vpn.service.agent)
#
# Strategy: avoid bootout entirely - it marks the service disabled in launchd's database
# and causes EIO errors on subsequent bootstrap attempts.
#
# - If daemon IS already registered with launchd (known but stopped/errored):
#     use `launchctl kickstart -k` to restart it in place
# - If daemon is NOT registered (brand new plist after fresh install):
#     use `launchctl enable` + `launchctl bootstrap` to register and start it
#
# Returns: 0 if all daemons successfully remediated, 1 if any failed
scRemediateDaemons()
{
  local remediationSuccess=true
  local -a daemonsToRemediate=("$@")

  for daemon in "${daemonsToRemediate[@]}"; do
    writeLog "Attempting to remediate $daemon..."

    if launchctl print "system/$daemon" &>/dev/null; then
      # Daemon is already registered - kickstart it without bootout
      writeLog "Daemon $daemon is registered - using kickstart to restart..."
      if launchctl kickstart -k "system/$daemon" 2>/dev/null; then
        writeLog "Kickstarted $daemon"
      else
        writeLog "Warning: kickstart failed for $daemon"
        remediationSuccess=false
        continue
      fi
    else
      # Daemon is not registered - find its plist and bootstrap it for the first time
      local plistPath=""
      for file in "${scFiles[@]}"; do
        if [[ "$file" == *"$daemon"* ]]; then
          plistPath="$file"
          break
        fi
      done

      if [[ -n "$plistPath" && -f "$plistPath" ]]; then
        writeLog "Daemon $daemon not registered - enabling and bootstrapping from $plistPath..."
        launchctl enable "system/$daemon" 2>/dev/null
        if launchctl bootstrap system "$plistPath" 2>/dev/null; then
          writeLog "Successfully bootstrapped $daemon"
        else
          writeLog "Failed to bootstrap $daemon"
          remediationSuccess=false
          continue
        fi
      else
        writeLog "Could not find plist for $daemon - cannot remediate"
        remediationSuccess=false
        continue
      fi
    fi

    # Verify it's running after either path
    sleep 2
    if ! launchctl print "system/$daemon" 2>/dev/null | grep -q "state = running"; then
      writeLog "Warning: $daemon still not in running state after remediation"
      remediationSuccess=false
    fi
  done

  if [[ "$remediationSuccess" == true ]]; then
    return 0
  else
    return 1
  fi
}

# Attempt to remediate non-running binaries by restarting their launch daemons
# Calls scRemediateDaemons() with all configured launch daemons
# Returns: 0 if remediation succeeded, 1 if failed
scRemediateBinaries()
{
  local remediationSuccess=true
  local -a daemonsToRestart=()
  
  # Collect unique daemons that need to be restarted
  for daemon in "${scLaunchDaemons[@]}"; do
    daemonsToRestart+=("$daemon")
  done
  
  # Use the daemon remediation function
  if ! scRemediateDaemons "${daemonsToRestart[@]}"; then
    remediationSuccess=false
  fi
  
  if [[ "$remediationSuccess" == true ]]; then
    return 0
  else
    return 1
  fi
}

scUninstallFull()
{
  writeLog "Performing full uninstall of Cisco Secure Client..."
  
  local uninstallScript="/opt/cisco/secureclient/bin/cisco_secure_client_uninstall.sh"
  
  # Check if uninstall script exists
  if [[ ! -x "$uninstallScript" ]]; then
    writeLog "Warning: Uninstall script not found at $uninstallScript"
    writeLog "Proceeding with manual cleanup..."
    scRemovePackageReceipts
    return 1
  fi
  
  # Run the uninstall script
  writeLog "Running Cisco Secure Client uninstall script..."
  if "$uninstallScript" 2>&1; then
    writeLog "Uninstall script completed"
  else
    writeLog "Warning: Uninstall script returned non-zero exit code"
  fi
  
  # Wait for uninstall operations to complete
  sleep 3
  
  # Validate uninstall was successful by checking key paths
  if scValidateUninstall; then
    writeLog "Uninstall validated successfully"
    return 0
  else
    writeLog "Uninstall validation failed - removing package receipts manually..."
    scRemovePackageReceipts
    
    # Re-validate after receipt removal
    if scValidateUninstall; then
      writeLog "Cleanup successful after removing package receipts"
      return 0
    else
      writeLog "Warning: Some components may still remain after cleanup"
      return 1
    fi
  fi
}

# Validate that Cisco Secure Client has been fully uninstalled
# Checks for key files and running processes
# Returns: 0 if fully uninstalled, 1 if components remain
scValidateUninstall()
{
  local componentsRemaining=0
  local -a remainingItems=()
  
  # Check if main application still exists
  if [[ -d "/Applications/Cisco/Cisco Secure Client.app" ]]; then
    writeLog "Main application still exists"
    remainingItems+=("Main application")
    (( componentsRemaining++ ))
  fi
  
  # Check for any running processes
  local -a processNames=(
    "vpnagentd"
    "csc_iseagentd"
    "csc_iseposture"
    "csc_swgagent"
    "acumbrellaagent"
    "acnvmagent"
    "csc_zta_agent"
  )
  
  for processName in "${processNames[@]}"; do
    if pgrep -x "$processName" > /dev/null 2>&1; then
      writeLog "Process still running: $processName"
      remainingItems+=("Process: $processName")
      (( componentsRemaining++ ))
      # Attempt to kill the process
      writeLog "Killing process: $processName"
      pkill -9 "$processName" 2>/dev/null
    fi
  done
  
  # Check for loaded launch daemons
  for daemon in "${scLaunchDaemons[@]}"; do
    if launchctl print "system/$daemon" &>/dev/null; then
      writeLog "Launch daemon still loaded: $daemon"
      remainingItems+=("Launch daemon: $daemon")
      (( componentsRemaining++ ))
      # Attempt to unload it
      writeLog "Unloading daemon: $daemon"
      launchctl bootout "system/$daemon" 2>/dev/null
    fi
  done
  
  if [[ $componentsRemaining -gt 0 ]]; then
    writeLog "Found $componentsRemaining component(s) remaining: ${remainingItems[*]}"
    return 1
  else
    writeLog "No Cisco Secure Client components detected"
    return 0
  fi
}

# Remove all Cisco Secure Client package installer receipts
# Extracts exact package IDs from each module's uninstall script
# This allows a fresh install to overwrite any remaining files
scRemovePackageReceipts()
{
  writeLog "Extracting package receipts from uninstall scripts..."
  
  local CSC_INSTPREFIX="/opt/cisco/secureclient"
  local POSTURE_BINDIR="${CSC_INSTPREFIX}/securefirewallposture/bin64/"
  local CISCO_SECURE_CLIENT_BINDIR="${CSC_INSTPREFIX}/bin"
  local NVM_BINDIR="${CSC_INSTPREFIX}/NVM/bin"
  
  # Define uninstall scripts and their locations (matching cisco_secure_client_uninstall.sh)
  local -a uninstallScripts=(
    "${CISCO_SECURE_CLIENT_BINDIR}/iseposture_uninstall.sh"
    "${CISCO_SECURE_CLIENT_BINDIR}/isecompliance_uninstall.sh"
    "${POSTURE_BINDIR}/posture_uninstall.sh"
    "${CISCO_SECURE_CLIENT_BINDIR}/umbrella_uninstall.sh"
    "${CISCO_SECURE_CLIENT_BINDIR}/amp_uninstall.sh"
    "${NVM_BINDIR}/nvm_uninstall.sh"
    "${CISCO_SECURE_CLIENT_BINDIR}/zta_uninstall.sh"
    "${CISCO_SECURE_CLIENT_BINDIR}/vpn_uninstall.sh"
  )
  
  local -a packageIDs=()
  local receiptsRemoved=0
  local receiptsFailed=0
  
  # Extract package ID from each uninstall script that exists
  for script in "${uninstallScripts[@]}"; do
    if [[ -f "$script" ]]; then
      local scriptName="$(basename "$script")"
      writeLog "Checking $scriptName for package ID..."
      
      # Extract package ID variable (e.g., CISCO_SECURE_CLIENT_ZTA_PACKAGE_ID=com.cisco.pkg.secureclient.zta)
      local packageID
      packageID=$(grep -E "PACKAGE_ID=com\.cisco\.(pkg\.)?(secureclient|anyconnect)" "$script" 2>/dev/null | head -1 | sed -E 's/.*PACKAGE_ID=([^[:space:]]+).*/\1/')
      
      if [[ -n "$packageID" ]]; then
        writeLog "  Found package ID: $packageID"
        packageIDs+=("$packageID")
        
        # Remove the package receipt immediately
        writeLog "  Running: pkgutil --forget $packageID"
        if pkgutil --forget "$packageID" >> /dev/null 2>&1; then
          writeLog "  Successfully removed package receipt"
          (( receiptsRemoved++ ))
        else
          writeLog "  Warning: Failed to remove package receipt (may not be installed)"
          (( receiptsFailed++ ))
        fi
      else
        writeLog "  No package ID found in $scriptName"
      fi
    fi
  done
  
  # If no package IDs were extracted from scripts, fall back to pattern search
  if [[ ${#packageIDs[@]} -eq 0 ]]; then
    writeLog "No package IDs extracted from uninstall scripts"
    writeLog "Falling back to pattern-based search using pkgutil..."
    
    local -a patternPackages=()
    while IFS= read -r pkg; do
      if [[ -n "$pkg" ]]; then
        patternPackages+=("$pkg")
      fi
    done < <(pkgutil --pkgs | grep -E "com\.cisco\.(pkg\.)?(secureclient|anyconnect)" 2>/dev/null)
    
    if [[ ${#patternPackages[@]} -eq 0 ]]; then
      writeLog "No Cisco packages found via pattern search either"
    else
      writeLog "Found ${#patternPackages[@]} package(s) via pattern search:"
      printf '  %s\n' "${patternPackages[@]}"
      
      for pkg in "${patternPackages[@]}"; do
        writeLog "Removing package receipt: $pkg"
        if pkgutil --forget "$pkg" >> /dev/null 2>&1; then
          writeLog "  Successfully removed"
          (( receiptsRemoved++ ))
        else
          writeLog "  Warning: Failed to remove (may not be installed)"
          (( receiptsFailed++ ))
        fi
      done
    fi
  fi
  
  # Print summary
  if [[ $receiptsRemoved -gt 0 ]] || [[ $receiptsFailed -gt 0 ]]; then
    writeLog "Package receipt removal summary:"
    writeLog "  Successfully removed: $receiptsRemoved"
    writeLog "  Failed/Not installed: $receiptsFailed"
  fi
  
  # Also remove any remaining installation directories
  if [[ -d "/opt/cisco/secureclient" ]]; then
    writeLog "Removing installation directory: /opt/cisco/secureclient"
    rm -rf "/opt/cisco/secureclient" 2>/dev/null
  fi
  
  if [[ -d "/opt/cisco/anyconnect" ]]; then
    writeLog "Removing legacy installation directory: /opt/cisco/anyconnect"
    rm -rf "/opt/cisco/anyconnect" 2>/dev/null
  fi
  
  if [[ -d "/Applications/Cisco/Cisco Secure Client.app" ]]; then
    writeLog "Removing application: /Applications/Cisco/Cisco Secure Client.app"
    rm -rf "/Applications/Cisco/Cisco Secure Client.app" 2>/dev/null
  fi
  
  if [[ -d "/Applications/Cisco/Cisco AnyConnect Secure Mobility Client.app" ]]; then
    writeLog "Removing legacy application: /Applications/Cisco/Cisco AnyConnect Secure Mobility Client.app"
    rm -rf "/Applications/Cisco/Cisco AnyConnect Secure Mobility Client.app" 2>/dev/null
  fi
  
  # Remove other Cisco applications that may remain
  local -a otherCiscoApps=(
    "/Applications/Cisco/Cisco AnyConnect DART.app"
    "/Applications/Cisco/Cisco AnyConnect Socket Filter.app"
    "/Applications/Cisco/Uninstall AnyConnect.app"
    "/Applications/Cisco/Uninstall AnyConnect DART.app"
    "/Applications/Cisco/Uninstall Cisco Secure Client.app"
  )
  
  for app in "${otherCiscoApps[@]}"; do
    if [[ -d "$app" ]]; then
      writeLog "Removing: $(basename "$app")"
      rm -rf "$app" 2>/dev/null
    fi
  done
  
  # Remove parent directory if empty
  if [[ -d "/Applications/Cisco" ]]; then
    if [[ -z "$(ls -A "/Applications/Cisco" 2>/dev/null)" ]]; then
      writeLog "Removing empty directory: /Applications/Cisco"
      rmdir "/Applications/Cisco" 2>/dev/null
    fi
  fi
  
  if [[ -d "/opt/cisco" ]]; then
    if [[ -z "$(ls -A "/opt/cisco" 2>/dev/null)" ]]; then
      writeLog "Removing empty directory: /opt/cisco"
      rmdir "/opt/cisco" 2>/dev/null
    fi
  fi
}

# Execute a single Jamf policy with specified event trigger
# Args: $1=policy event trigger to run
# Logs the outcome via writeLog function
# Returns: 0 if policy succeeded, 1 if failed
scRunJamfPolicy()
{
  local policyEvent="$1"
  
  if [[ -z "$policyEvent" ]]; then
    writeLog "Error: No policy event trigger specified"
    return 1
  fi
  
  writeLog "Running Jamf policy with event trigger: $policyEvent"
  local jamf_output
  jamf_output=$(/usr/local/bin/jamf policy -event "$policyEvent" 2>&1)
  local jamf_rc=$?

  # "No policies were found" returns exit 0 from jamf but is not a success
  if echo "$jamf_output" | grep -q "No policies were found"; then
    writeLog "Policy not found or not in scope for trigger: $policyEvent"
    return 1
  fi

  # If there is a "Script exit code:" line, verify it is 0 (catches script failures in script-based policies)
  if echo "$jamf_output" | grep -q "Script exit code:" && ! echo "$jamf_output" | grep -q "Script exit code: 0"; then
    writeLog "Policy failed or did not complete successfully (script returned non-zero)"
    return 1
  fi

  # Use jamf's actual exit code as the final arbiter (covers package-only policies with no script output)
  if [[ $jamf_rc -eq 0 ]]; then
    writeLog "Policy completed successfully"
    return 0
  else
    writeLog "Policy failed or did not complete successfully"
    return 1
  fi
}

# Main execution
vpn_connected=false
if ! scConnectedCheck; then
  vpn_connected=true
fi

scVersionTest
scLaunchDaemonsCheck
scBinariesCheck
scFilesCheck

if [[ $runPolicy -gt 0 ]]; then
  # Record the issues in the state file for orchestrator script (must create dict first)
  combinedReason=""
  if [[ ${#reasonArray[@]} -eq 1 ]]; then
    combinedReason="${reasonArray[0]}"
  else
    combinedReason="${runPolicyReason}: $(printf '%s; ' "${reasonArray[@]}" | sed 's/; $//')"
  fi
  record_needs_action "$combinedReason"
  
  # Increment deferral if VPN is connected (after recording state so dict exists)
  if [[ "$vpn_connected" == true ]]; then
    writeLog "VPN is connected - incrementing deferral count..."
    increment_deferral
  fi
  
  # Exit if VPN is connected (after recording state with incremented deferral)
  if [[ "$vpn_connected" == true ]]; then
    writeLog "VPN is connected. Exiting to avoid disruption..."
    exit 0
  fi
  
  # Report issues found
  if [[ $runPolicy -eq 1 ]]; then
    writeLog "Found: $runPolicy reason to remediate Secure Client"
  else
    writeLog "Found: $runPolicy reasons to remediate Secure Client"
  fi
  for reason in "${reasonArray[@]}"; do
    writeLog "$reason"
  done
  
  # Attempt remediation based on the issue type
  remediationAttempted=false
  remediationSucceeded=false
  
  case "$runPolicyReason" in
    launchdaemonNotRunning)
      writeLog "Attempting to remediate launch daemons..."
      remediationAttempted=true
      if scRemediateDaemons "${scLaunchDaemons[@]}"; then
        writeLog "Launch daemon remediation succeeded"
        remediationSucceeded=true
      else
        writeLog "Launch daemon remediation failed, will run Jamf policy"
      fi
      ;;
      
    binaryNotRunning)
      writeLog "Attempting to remediate binaries..."
      remediationAttempted=true
      
      # Check if csc_swgagent or csc_zta_agent are not running
      # These require their configuration JSON files, so run their policies first
      needsSwgConfig=false
      needsZtaConfig=false
      
      for binary in "${notRunningBinariesArray[@]}"; do
        if [[ "$binary" == "csc_swgagent" ]]; then
          needsSwgConfig=true
        elif [[ "$binary" == "csc_zta_agent" ]]; then
          needsZtaConfig=true
        fi
      done
      
      # Run configuration policies if needed
      if [[ "$needsSwgConfig" == true ]] && [[ -n "$swgJSONPolicy" ]]; then
        writeLog "csc_swgagent not running - deploying SWG configuration..."
        if scRunJamfPolicy "$swgJSONPolicy"; then
          writeLog "SWG configuration deployed, waiting 5 seconds for process to start..."
          sleep 5
          # Check if csc_swgagent is now running
          if pgrep -f "csc_swgagent" > /dev/null 2>&1; then
            writeLog "csc_swgagent is now running"
            # Remove from notRunningBinariesArray
            notRunningBinariesArray=("${notRunningBinariesArray[@]/csc_swgagent}")
          else
            writeLog "Warning: csc_swgagent still not running after configuration"
          fi
        else
          writeLog "Warning: SWG configuration policy failed"
        fi
      fi
      
      if [[ "$needsZtaConfig" == true ]] && [[ -n "$ztaJSONPolicy" ]]; then
        writeLog "csc_zta_agent not running - deploying ZTA configuration..."
        if scRunJamfPolicy "$ztaJSONPolicy"; then
          writeLog "ZTA configuration deployed, waiting 5 seconds for process to start..."
          sleep 5
          # Check if csc_zta_agent is now running
          if pgrep -f "csc_zta_agent" > /dev/null 2>&1; then
            writeLog "csc_zta_agent is now running"
            # Remove from notRunningBinariesArray
            notRunningBinariesArray=("${notRunningBinariesArray[@]/csc_zta_agent}")
          else
            writeLog "Warning: csc_zta_agent still not running after configuration"
          fi
        else
          writeLog "Warning: ZTA configuration policy failed"
        fi
      fi
      
      # If there are still binaries not running, try daemon remediation
      if [[ ${#notRunningBinariesArray[@]} -gt 0 ]]; then
        writeLog "Attempting to remediate remaining binaries by restarting daemons..."
        if scRemediateBinaries; then
          writeLog "Binary remediation succeeded"
          remediationSucceeded=true
        else
          writeLog "Binary remediation failed, will run CSC installer policy"
        fi
      else
        writeLog "All binaries remediated via configuration policies"
        remediationSucceeded=true
      fi
      ;;
      
    notInstalled|versionMismatch)
      writeLog "Files missing or version mismatch - proceeding directly to Jamf policy"
      ;;
  esac
  
  # If remediation wasn't attempted or failed, run Jamf policies
  if [[ "$remediationAttempted" == false ]] || [[ "$remediationSucceeded" == false ]]; then
    # Run CSC uninstaller function to ensure clean state
    scUninstallFull
    

    # Run configuration policies if specified
    if [[ -n "$csaProfilePolicy" ]]; then
      scRunJamfPolicy "$csaProfilePolicy"
    fi

    if [[ -n "$ztaJSONPolicy" ]]; then
      scRunJamfPolicy "$ztaJSONPolicy"
    fi
    
    if [[ -n "$swgJSONPolicy" ]]; then
      scRunJamfPolicy "$swgJSONPolicy"
    fi

    # Run CSC installer policy (required)
    scRunJamfPolicy "$cscInstallerPolicy"

  else
    writeLog "Remediation succeeded - Secure Client is now running properly"
    clear_state
  fi
else
  writeLog "Secure Client installed, up to date, and running..."
  clear_state
fi

exit 0
