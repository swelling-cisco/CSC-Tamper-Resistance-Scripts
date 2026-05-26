#!/bin/bash

# =============================================================================
# Script:   csc_config_enforcement.sh
# Purpose:  Validates the integrity of Cisco Secure Client module
#           configuration files on macOS endpoints managed through Jamf Pro,
#           and remediates detected issues by triggering the appropriate
#           configuration deployment policy.
#
# Overview:
#   This script provides a unified mechanism for enforcing the integrity of
#   VPN profile, Umbrella OrgInfo.json, and ZTA enrollment JSON configuration
#   files. A single script instance handles all three profile types, with
#   behavior tailored per profile type based on the input parameters passed
#   at policy execution time.
#
#   On each execution, the script processes each populated parameter ($4
#   through $11) in sequence, performing the following steps for each:
#     1. Parses the comma-separated input string to extract the filename,
#        expected SHA256 hash, Jamf policy event trigger, and profile folder
#        type.
#     2. Builds the expected file path based on the profile folder type.
#     3. Applies any profile-type-specific pre-checks before hash validation:
#
#        ZTA profiles:
#          Enumerates all JSON files present in the ZTA enrollment directory.
#          If no JSON files are found, triggers the deployment policy to
#          restore the missing enrollment file. If more than one JSON file is
#          present, removes all extraneous files, retaining only the expected
#          enrollment file, before proceeding with hash validation. This
#          prevents ZTA enrollment conflicts caused by the presence of
#          multiple JSON files in the enrollment directory.
#
#        Umbrella profiles:
#          Checks for hash consistency between the primary OrgInfo.json and
#          any cached copies present in the Umbrella data and SWG
#          subdirectories. If a hash inconsistency is found, the stale
#          subdirectories are deleted and the deployment policy is triggered
#          to restore the correct configuration. VPN connectivity is checked
#          before any Umbrella remediation is attempted, with deferral logic
#          applied if the VPN is active.
#
#        VPN profiles:
#          No additional pre-checks are performed. Standard file existence
#          and hash validation proceeds directly.
#
#     4. Verifies that the configuration file exists at the expected path.
#        If the file is missing, triggers the corresponding Jamf deployment
#        policy to restore it. For Umbrella profiles, VPN connectivity is
#        checked before remediation is attempted, and the deferral counter
#        is incremented if the VPN is active.
#     5. Computes the SHA256 hash of the file and compares it against the
#        expected value. If a mismatch is detected, triggers the deployment
#        policy to overwrite the file with the correct content. For Umbrella
#        profiles, the Umbrella data subdirectories are deleted and the VPN
#        agent process is restarted after the deployment policy completes to
#        force it to reinitialize with the correct configuration.
#     6. Records compliance state, deferral counts, and first-detection
#        timestamps in the shared enforcement state file for use by the
#        Orchestrator Script (csc_enforcement_orchestrator.sh).
#
#   This script is intended to be assigned to a dedicated Jamf Pro policy
#   for each module configuration type, with each policy configured with a
#   unique custom event trigger and a single populated Parameter $4 value
#   defining the configuration file to be enforced. Multiple profile checks
#   can be consolidated into a single policy by populating Parameters $4
#   through $11, though this approach is not used in the default framework
#   configuration described in this guide.
#
# Usage:
#   Deployed via Jamf Pro policy. To invoke manually on a managed device:
#     sudo jamf policy -event <custom_event_trigger>
#
#   Examples:
#     sudo jamf policy -event csc_enforce_vpn
#     sudo jamf policy -event csc_enforce_umbrella
#     sudo jamf policy -event csc_enforce_zta
#
# Parameters (configured in the Jamf Pro policy):
#   $4 through $11 - Profile Check   Each parameter accepts a single profile
#                                    check definition as a comma-separated
#                                    string in the following format:
#
#                                      fileName,expectedSHA256Hash,
#                                      policyEventTrigger,profileType
#
#                                    fileName          - The filename of the
#                                      configuration file to validate
#                                      (e.g., OrgInfo.json).
#                                    expectedSHA256Hash - The lowercase
#                                      SHA256 hash of the known-good version
#                                      of the file. Calculate this value by
#                                      running the corresponding write script
#                                      on a test device and executing:
#                                        shasum -a 256 /path/to/configfile \
#                                        | awk '{print $1}'
#                                      This value must be recalculated and
#                                      updated in the policy whenever the
#                                      corresponding write script is updated.
#                                      Hash values are case-sensitive and
#                                      must be entered in lowercase.
#                                    policyEventTrigger - The custom event
#                                      trigger name of the Jamf Pro policy
#                                      that deploys the correct version of
#                                      this configuration file
#                                      (e.g., deploy_umbrella_profile).
#                                      Must exactly match the trigger name
#                                      configured in the deployment policy.
#                                    profileType       - The module type
#                                      used to determine the expected file
#                                      path and apply profile-type-specific
#                                      logic. Accepted values:
#                                        vpn      - /opt/cisco/secureclient/
#                                                   vpn/profile/
#                                        umbrella - /opt/cisco/secureclient/
#                                                   umbrella/
#                                        zta      - /opt/cisco/secureclient/
#                                                   zta/enrollment_choices/
#
#                                    Example parameter values:
#                                      VPN:
#                                        Cert_Profile.xml,abc123,
#                                        deploy_vpn_profile,vpn
#                                      Umbrella:
#                                        OrgInfo.json,def456,
#                                        deploy_umbrella_profile,umbrella
#                                      ZTA:
#                                        OrgID_ZTA_Enroll_Cert.json,ghi789,
#                                        deploy_zta_profile,zta
#
#                                    Leave unused parameters blank.
#
# Configuration:
#   The following variables can be adjusted to suit your environment:
#
#   STATE_FILE          - Full path to the shared plist file used to record
#                         compliance state, deferral counts, and
#                         first-detection timestamps for each configuration
#                         profile check performed by this script.
#                         Default:
#                           /Library/Application Support/
#                           SecureClientEnforcement/
#                           csc_enforcement_state.plist
#                         IMPORTANT: This value must be identical across
#                         csc_enforcement_orchestrator.sh,
#                         csc_module_enforcement.sh, and
#                         csc_config_enforcement.sh. A path mismatch between
#                         any of these scripts will prevent compliance issues
#                         detected by configuration file checks from being
#                         reflected in the shared state readable by the
#                         orchestrator, causing the coordinated remediation
#                         and deferral logic that depends on that shared
#                         state to not function as intended.
#
#   DEFERRAL_THRESHOLD  - Number of consecutive deferred check-ins permitted
#                         before the user is required to acknowledge the
#                         remediation prompt. Default: 3.
#                         IMPORTANT: This value should be set consistently
#                         across csc_enforcement_orchestrator.sh,
#                         csc_module_enforcement.sh, and
#                         csc_config_enforcement.sh to ensure predictable
#                         deferral behavior across the enforcement framework.
#
#   MAX_DEFERRAL_HOURS  - Maximum number of hours a compliance issue may
#                         remain unaddressed before the deferral threshold
#                         is considered breached, regardless of check-in
#                         count. Default: 4.
#                         IMPORTANT: This value should be set consistently
#                         across csc_enforcement_orchestrator.sh,
#                         csc_module_enforcement.sh, and
#                         csc_config_enforcement.sh to ensure predictable
#                         deferral behavior across the enforcement framework.
#
# Requirements:
#   - The Jamf Pro deployment policies referenced by the policyEventTrigger
#     value in each parameter must be configured with matching custom event
#     trigger names before this script is deployed.
#   - The Cisco Secure Client VPN binary must be present at:
#       /opt/cisco/secureclient/bin/vpn
#     for VPN connection state detection used by Umbrella deferral logic.
#   - Script must be executed in the root context, as is the case when
#     run via a Jamf Pro policy.
# =============================================================================

#########################
# State Management
# Integrates with csc_enforcement_orchestrator.sh
#########################
STATE_FILE="/Library/Application Support/SecureClientEnforcement/csc_enforcement_state.plist"

# Will be set dynamically based on policyEvent parameter
POLICY_ID=""

# Configurable thresholds (should match orchestrator)
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
    local log_id="${POLICY_ID:-csc_enforce}"
    /usr/bin/logger -t "[CSC-Enforce]" "${log_id}: ${msg}"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [${log_id}] ${msg}"
}

record_needs_action() {
    local reason="$1"
    init_state_file
    local now
    now=$(date +%s)
    
    # Check if entry already exists (preserve first_detected time)
    local existing_time
    existing_time=$(/usr/libexec/PlistBuddy -c "Print :${POLICY_ID}:first_detected" "$STATE_FILE" 2>/dev/null)
    
    # Preserve deferral count before deleting the policy entry.
    local existing_count
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
    
    # Initialize or preserve deferral count
    /usr/libexec/PlistBuddy -c "Add :${POLICY_ID}:deferred_count integer ${existing_count}" "$STATE_FILE" 2>/dev/null
    
    log_message "Recorded needs_action: ${reason}"
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
    if /usr/libexec/PlistBuddy -c "Print :${POLICY_ID}" "$STATE_FILE" &>/dev/null; then
        /usr/libexec/PlistBuddy -c "Delete :${POLICY_ID}" "$STATE_FILE" 2>/dev/null
        log_message "Cleared state (compliance verified)"
    fi
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

#########################
# Helper Functions
#########################

# Umbrella-specific paths
umbrellaDataFolderPath="/opt/cisco/secureclient/umbrella/data"
umbrellaSWGFolderPath="/opt/cisco/secureclient/umbrella/SWG"

# Track if VPN agent needs restart (umbrella only)
needsKill=false

# Check if VPN is connected (used for umbrella only)
scConnectedCheck() {
    if [[ $(/opt/cisco/secureclient/bin/vpn state 2>/dev/null | grep -c "state: Connected") -gt 0 ]]; then
        log_message "VPN is connected"
        return 0  # Connected
    else
        log_message "VPN is NOT connected"
        return 1  # Not connected
    fi
}

# Kill VPN agent so launchd restarts it and picks up the new OrgInfo.json (umbrella only).
# vpnagentd runs under a KeepAlive launchd job - killing the process is sufficient;
# launchd will restart it automatically without any bootout/bootstrap needed.
killVPNAgent() {
    local pid
    pid=$(pgrep -x vpnagentd 2>/dev/null)

    if [[ -z "$pid" ]]; then
        log_message "vpnagentd is not running - nothing to kill"
        return 0
    fi

    log_message "Killing vpnagentd (PID: ${pid}) so launchd restarts it with new config..."
    kill -9 "$pid" 2>/dev/null
    log_message "Killed vpnagentd process: ${pid}"

    # Wait for launchd to restart the process (up to 30 seconds)
    local timeout=30
    local elapsed=0
    while [[ $elapsed -lt $timeout ]]; do
        sleep 2
        elapsed=$((elapsed + 2))
        local newPID
        newPID=$(pgrep -x vpnagentd 2>/dev/null)
        if [[ -n "$newPID" && "$newPID" != "$pid" ]]; then
            log_message "vpnagentd restarted by launchd (new PID: ${newPID})"
            return 0
        fi
    done

    log_message "Warning: vpnagentd did not restart within ${timeout} seconds"
    return 1
}

# Delete umbrella data folders (umbrella only)
deleteUmbrellaFolders() {
    if [[ -d "$umbrellaDataFolderPath" ]]; then
        rm -rf "$umbrellaDataFolderPath"
        log_message "Deleted umbrella data folder"
    fi
    if [[ -d "$umbrellaSWGFolderPath" ]]; then
        rm -rf "$umbrellaSWGFolderPath"
        log_message "Deleted umbrella SWG folder"
    fi
}

# Build the check path based on profile folder type
buildCheckPath() {
    local profileFolder="$1"
    local basePath="/opt/cisco/secureclient"
    
    case "$profileFolder" in
        vpn)
            echo "${basePath}/vpn/profile"
            ;;
        umbrella)
            echo "${basePath}/umbrella"
            ;;
        zta)
            echo "${basePath}/zta/enrollment_choices"
            ;;
        *)
            # Fallback: append /profile for unknown types
            echo "${basePath}/${profileFolder}/profile"
            ;;
    esac
}

# Check if profile type requires VPN disconnect for remediation
requiresVPNCheck() {
    local profileFolder="$1"
    case "$profileFolder" in
        umbrella)
            return 0  # true - requires VPN check
            ;;
        *)
            return 1  # false - no VPN check needed
            ;;
    esac
}

# Handle VPN connection check and deferral for umbrella/zta
# Returns 0 if we should proceed, 1 if we should defer
handleVPNCheckAndDeferral() {
    local profileFolder="$1"
    local reason="$2"
    
    if ! requiresVPNCheck "$profileFolder"; then
        return 0  # Proceed - no VPN check needed for this type
    fi
    
    if scConnectedCheck; then
        # VPN is connected - record state and increment deferral
        record_needs_action "$reason"
        increment_deferral
        log_message "VPN connected - deferring remediation for $profileFolder"
        return 1  # Defer
    fi
    
    return 0  # Proceed - VPN not connected
}

#########################
# ZTA-specific Functions
#########################

cleanupZTAFolder() {
    local checkPath="$1"
    local expectedFileName="$2"
    
    log_message "Checking for and removing extraneous .json files in $checkPath..."
    
    # Save and enable nullglob so the glob expands to nothing when no files match
    local null_glob_was_set
    shopt -q nullglob && null_glob_was_set=true || null_glob_was_set=false
    shopt -s nullglob
    
    for file in "$checkPath"/*.json; do
        local base_filename
        base_filename=$(basename "$file")
        if [[ "$base_filename" != "$expectedFileName" ]]; then
            log_message "Removing unwanted JSON file: $file"
            rm -f "$file"
        fi
    done
    
    # Restore original nullglob setting
    if [[ "$null_glob_was_set" == false ]]; then
        shopt -u nullglob
    fi
    
    log_message "Finished cleaning up .json files"
}

countZTAFiles() {
    local checkPath="$1"
    
    local null_glob_was_set
    shopt -q nullglob && null_glob_was_set=true || null_glob_was_set=false
    shopt -s nullglob
    
    local json_files=("$checkPath"/*.json)
    local count=${#json_files[@]}
    
    if [[ "$null_glob_was_set" == false ]]; then
        shopt -u nullglob
    fi
    
    echo "$count"
}

#########################
# Umbrella-specific Functions
#########################

checkUmbrellaDataFolderHash() {
    local fileName="$1"
    local filePath="$2"
    
    local globalDataFolderJsonPath="/opt/cisco/secureclient/umbrella/data/regionaldata/global/data/$fileName"
    local legacyDataFolderJsonPath="/opt/cisco/secureclient/umbrella/data/$fileName"
    
    if [[ -f "$filePath" && -f "$globalDataFolderJsonPath" ]]; then
        local globalDataFolderJsonHash
        globalDataFolderJsonHash=$(shasum -a 256 "$globalDataFolderJsonPath" | awk '{print $1}')
        local mainJsonHash
        mainJsonHash=$(shasum -a 256 "$filePath" | awk '{print $1}')
        
        if [[ "$mainJsonHash" != "$globalDataFolderJsonHash" ]]; then
            log_message "Hash mismatch: $fileName (main vs data folder)"
            if ! handleVPNCheckAndDeferral "umbrella" "Hash mismatch: $fileName"; then
                return 1
            fi
            record_needs_action "Hash mismatch: $fileName"
            deleteUmbrellaFolders
            needsKill=true
            return 1
        fi
    elif [[ -f "$filePath" && -f "$legacyDataFolderJsonPath" ]]; then
        local legacyDataFolderJsonHash
        legacyDataFolderJsonHash=$(shasum -a 256 "$legacyDataFolderJsonPath" | awk '{print $1}')
        local mainJsonHash
        mainJsonHash=$(shasum -a 256 "$filePath" | awk '{print $1}')
        
        if [[ "$mainJsonHash" != "$legacyDataFolderJsonHash" ]]; then
            log_message "Hash mismatch: $fileName (main vs legacy data folder)"
            if ! handleVPNCheckAndDeferral "umbrella" "Hash mismatch: $fileName"; then
                return 1
            fi
            record_needs_action "Hash mismatch: $fileName"
            deleteUmbrellaFolders
            needsKill=true
            return 1
        fi
    fi
    
    return 0
}

#########################
# Main Profile Check Function
#########################

profileCheck() {
    local input_string="$1"
    local fileName hashValue policyEvent profileFolder
    
    # Split input line & assign to variables for processing
    read -r fileName hashValue policyEvent profileFolder <<< "$(echo "$input_string" | awk -F',' '{print $1, $2, $3, $4}')"
    
    # Validate required parameters
    if [[ -z "$fileName" || -z "$hashValue" || -z "$policyEvent" || -z "$profileFolder" ]]; then
        log_message "ERROR: Missing required parameters. Format: fileName,hashValue,policyEvent,profileFolder"
        return 1
    fi
    
    # Set POLICY_ID dynamically based on policyEvent, allow orchestrator override
    local current_event_override
    current_event_override=$(/usr/libexec/PlistBuddy -c "Print :global:current_event" "$STATE_FILE" 2>/dev/null)
    if [[ -n "$current_event_override" ]]; then
        POLICY_ID="$current_event_override"
    else
        POLICY_ID="$policyEvent"
    fi
    
    # Build the check path based on profile folder type
    local checkPath
    checkPath=$(buildCheckPath "$profileFolder")
    local filePath="$checkPath/$fileName"
    
    log_message "Processing: $fileName in $checkPath (policy: $policyEvent)"
    
    #########################
    # ZTA-specific: Check for extraneous files first
    #########################
    if [[ "$profileFolder" == "zta" ]]; then
        local numFiles
        numFiles=$(countZTAFiles "$checkPath")
        
        if [[ "$numFiles" -eq 0 ]]; then
            log_message "No .json files found in $checkPath"
            # Check VPN before remediation
            if handleVPNCheckAndDeferral "$profileFolder" "ZTA JSON missing: $fileName"; then
                record_needs_action "ZTA JSON missing: $fileName"
                jamf policy -event "$policyEvent"
            fi
            return 0
        elif [[ "$numFiles" -gt 1 ]]; then
            cleanupZTAFolder "$checkPath" "$fileName"
        fi
    fi
    
    #########################
    # Umbrella-specific: Check data folder hash consistency
    #########################
    if [[ "$profileFolder" == "umbrella" ]]; then
        if ! checkUmbrellaDataFolderHash "$fileName" "$filePath"; then
            # Data folder hash mismatch - folders have been deleted, trigger policy to redeploy
            jamf policy -event "$policyEvent"
            return 0
        fi
    fi
    
    #########################
    # Common: Check if file exists
    #########################
    if [[ ! -f "$filePath" ]]; then
        log_message "$fileName not present at $filePath"
        
        # Check VPN before remediation (umbrella only)
        if ! handleVPNCheckAndDeferral "$profileFolder" "File missing: $fileName"; then
            return 0  # Deferred
        fi
        
        # Record state and remediate
        record_needs_action "File missing: $fileName"
        
        if [[ "$profileFolder" == "umbrella" ]]; then
            needsKill=true
            deleteUmbrellaFolders
        fi
        
        jamf policy -event "$policyEvent"
        return 0
    fi
    
    #########################
    # Common: Verify file hash
    #########################
    local localHash
    localHash=$(shasum -a 256 "$filePath" | awk '{print $1}')
    
    if [[ "$localHash" == "$hashValue" ]]; then
        log_message "Profile $fileName verified (hash match)"
        
        # Umbrella-specific: Check if required folders exist even when hash is correct
        if [[ "$profileFolder" == "umbrella" && "$needsKill" != true ]]; then
            if [[ ! -d "$umbrellaDataFolderPath" ]] || [[ ! -d "$umbrellaSWGFolderPath" ]]; then
                log_message "Required umbrella folders missing despite correct hash"
                needsKill=true
            fi
        fi
        
        # Clear state - file is compliant
        clear_state
        return 0
    fi
    
    #########################
    # Hash mismatch - remediation needed
    #########################
    log_message "Hash mismatch for $fileName (local: $localHash, expected: $hashValue)"
    
    # Check VPN before remediation (umbrella/zta only)
    if ! handleVPNCheckAndDeferral "$profileFolder" "Hash mismatch: $fileName"; then
        return 0  # Deferred
    fi
    
    # Record state
    record_needs_action "Hash mismatch: $fileName"
    
    # Profile-specific remediation
    case "$profileFolder" in
        umbrella)
            needsKill=true
            deleteUmbrellaFolders
            jamf policy -event "$policyEvent"
            ;;
        zta)
            # ZTA: Remove file before policy writes new one to /tmp then moves it
            rm -f "$filePath"
            jamf policy -event "$policyEvent"
            ;;
        *)
            # VPN: Standard remediation
            jamf policy -event "$policyEvent"
            ;;
    esac
    
    return 0
}

#########################
# Main Execution
#########################

# Process Jamf parameters $4 through $11 (allowing up to 8 profile checks)
for param in "$4" "$5" "$6" "$7" "$8" "$9" "${10}" "${11}"; do
    if [[ -n "$param" ]]; then
        profileCheck "$param"
    fi
done

# Umbrella-specific: Kill VPN agent if needed
if [[ "$needsKill" == true ]]; then
    killVPNAgent
fi

exit 0

