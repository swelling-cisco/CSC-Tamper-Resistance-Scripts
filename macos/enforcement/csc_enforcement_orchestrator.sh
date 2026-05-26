#!/bin/bash

# =============================================================================
# Script:   csc_enforcement_orchestrator.sh
# Purpose:  Coordinates the macOS Cisco Secure Client tamper resistance
#           enforcement framework by aggregating compliance state reported by
#           individual enforcement scripts and determining the appropriate
#           response based on the overall compliance posture of the device.
#
# Overview:
#   This script serves as the central coordination layer of the macOS Secure
#   Client tamper resistance framework. It does not perform compliance checks
#   directly. Instead, it reads the shared enforcement state written by the
#   Module Enforcement Script (csc_module_enforcement.sh) and Configuration
#   Enforcement Script (csc_config_enforcement.sh), and responds based on
#   the aggregated compliance posture of the device.
#
#   On each execution, the orchestrator follows this sequence:
#     1. Initializes the shared state file if it does not yet exist.
#     2. Invokes all configured enforcement policies in sequence to refresh
#        the current compliance state.
#     3. If all policies report a compliant state, clears the shared state
#        file and exits cleanly.
#     4. If one or more policies report a compliance issue, evaluates whether
#        the configured deferral threshold or maximum deferral time window
#        has been exceeded. If neither threshold has been reached, exits
#        without taking further action.
#     5. Once a deferral threshold is breached, checks whether the VPN is
#        currently connected. If the VPN is active, presents the user with
#        a jamfHelper dialog prompting them to either proceed with remediation
#        or defer. If the user defers, increments the global deferral counter
#        and exits.
#     6. If the user approves or the VPN is not connected, disconnects the
#        VPN if necessary, triggers only the remediation policies relevant to
#        the detected issues, and re-runs all validation policies to confirm
#        that compliance has been restored.
#     7. Presents a follow-up jamfHelper notification informing the user
#        whether remediation succeeded or failed.
#
#   This script is intended to be assigned to a Jamf Pro policy configured
#   with a Recurring Check-in trigger and an additional custom event trigger
#   for on-demand invocation during testing and troubleshooting.
#
# Usage:
#   Deployed via Jamf Pro policy. To invoke manually on a managed device:
#     sudo jamf policy -event <custom_event_trigger>
#
#   Example:
#     sudo jamf policy -event csc_orchestrate
#
# Parameters (configured in the Jamf Pro policy):
#   $5 - CSC Enforce Policy Event    Custom event trigger for the Module
#                                    Enforcement policy
#                                    (e.g., csc_enforce_modules)
#   $6 - VPN Enforce Config Event    Custom event trigger for the VPN
#                                    Configuration Enforcement policy
#                                    (e.g., csc_enforce_vpn)
#   $7 - Umbrella Enforce Config     Custom event trigger for the Umbrella
#        Event                       Configuration Enforcement policy
#                                    (e.g., csc_enforce_umbrella)
#   $8 - ZTA Enforce Config Event    Custom event trigger for the ZTA
#                                    Configuration Enforcement policy
#                                    (e.g., csc_enforce_zta)
#
# Configuration:
#   The following variables can be adjusted to suit your environment:
#
#   STATE_FILE        - Full path to the shared plist file used by all
#                       enforcement scripts to track compliance state,
#                       deferral counts, and first-detection timestamps.
#                       Default:
#                         /Library/Application Support/
#                         SecureClientEnforcement/
#                         csc_enforcement_state.plist
#                       IMPORTANT: This value must be identical across
#                       csc_enforcement_orchestrator.sh,
#                       csc_module_enforcement.sh, and
#                       csc_config_enforcement.sh. A path mismatch between
#                       any of these scripts will prevent the orchestrator
#                       from reading compliance state written by the
#                       enforcement scripts, breaking the coordination layer
#                       of the tamper resistance framework entirely.
#
#   DEFERRAL_THRESHOLD - Number of consecutive deferred check-ins permitted
#                        before the user is required to acknowledge the
#                        remediation prompt. Default: 3. Adjust based on
#                        your organization's acceptable remediation latency.
#
#   MAX_DEFERRAL_HOURS - Maximum number of hours a compliance issue may
#                        remain unaddressed before the deferral threshold is
#                        considered breached, regardless of check-in count.
#                        Default: 4. Adjust to align with your
#                        organization's security requirements.
#
# Requirements:
#   - All enforcement policies referenced in Parameters $5 through $8 must
#     be configured in Jamf Pro with matching custom event trigger names
#     before this script is deployed.
#   - jamfHelper must be present at:
#       /Library/Application Support/JAMF/bin/jamfHelper.app/
#       Contents/MacOS/jamfHelper
#   - The Cisco Secure Client VPN binary must be present at:
#       /opt/cisco/secureclient/bin/vpn
#     for VPN connection state detection and disconnect functionality.
#   - Script must be executed in the root context, as is the case when
#     run via a Jamf Pro policy.
# =============================================================================

STATE_FILE="/Library/Application Support/SecureClientEnforcement/csc_enforcement_state.plist"
POLICY_ID="orchestrator"
DEFERRAL_THRESHOLD=3
MAX_DEFERRAL_HOURS=4

# Path to the jamfHelper binary
JAMF_HELPER="/Library/Application Support/JAMF/bin/jamfHelper.app/Contents/MacOS/jamfHelper"
# Path to a generic icon (Cisco Secure Client icon is used if found, else a system icon)
ICON="/Applications/Cisco/Cisco Secure Client.app/Contents/Resources/vpngui.icns"
if [[ ! -f "$ICON" ]]; then
    ICON="/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/AlertNoteIcon.icns"
fi

# Parse Jamf policy event triggers from parameters 5, 6, 7, 8
cscEnforcePolicy="$5"  # CSC + Modules enforce policy
vpnEnforcePolicy="$6"  # Cisco AnyConnect VPN profile enforce policy
swgEnforcePolicy="$7"  # Secure Web Gateway/Umbrella JSON enforce policy
ztaEnforcePolicy="$8"  # Zero Trust Access JSON enforce policy

# Validate a policy ID for safe use as a PlistBuddy key path component.
is_valid_policy_id() {
    if [[ "$1" =~ ^[A-Za-z0-9._-]+$ ]]; then
        return 0
    fi
    return 1
}

# Initialize enforcement policies array
ENFORCEMENT_POLICIES=()

# Add non-empty custom triggers to the array, rejecting any with unsafe characters
for _policy_param in "$cscEnforcePolicy" "$vpnEnforcePolicy" "$swgEnforcePolicy" "$ztaEnforcePolicy"; do
    if [[ -n "$_policy_param" ]]; then
        if is_valid_policy_id "$_policy_param"; then
            ENFORCEMENT_POLICIES+=("$_policy_param")
        else
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] [${POLICY_ID}] WARNING: Ignoring policy parameter with invalid characters: ${_policy_param}" >&2
        fi
    fi
done
unset _policy_param

log_message() {
    /usr/bin/logger -t "[CSC-Enforce]" "${POLICY_ID}: $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [${POLICY_ID}] $1" >&2
}

# Initialize state file if it doesn't exist
init_state_file() {
    local dir
    dir=$(dirname "$STATE_FILE")
    [[ ! -d "$dir" ]] && mkdir -p "$dir"
    
    if [[ -f "$STATE_FILE" ]]; then
        if ! /usr/libexec/PlistBuddy -c "Print" "$STATE_FILE" >/dev/null 2>&1; then
            log_message "State file exists but is corrupted - recreating"
            rm -f "$STATE_FILE"
        fi
    fi
    
    if [[ ! -f "$STATE_FILE" ]]; then
        cat > "$STATE_FILE" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
</dict>
</plist>
EOF
        log_message "Created new state file"
    fi
}

set_current_policy_event() {
    local event="$1"
    if [[ -z "$event" ]]; then return 0; fi
    init_state_file
    /usr/libexec/PlistBuddy -c "Add :global dict" "$STATE_FILE" 2>/dev/null
    /usr/libexec/PlistBuddy -c "Delete :global:current_event" "$STATE_FILE" 2>/dev/null
    /usr/libexec/PlistBuddy -c "Add :global:current_event string ${event}" "$STATE_FILE"
}

clear_current_policy_event() {
    if [[ ! -f "$STATE_FILE" ]]; then return 0; fi
    /usr/libexec/PlistBuddy -c "Delete :global:current_event" "$STATE_FILE" 2>/dev/null
}

# Check if ANY policy needs action
any_policy_needs_action() {
    if [[ ${#ENFORCEMENT_POLICIES[@]} -eq 0 ]]; then
        log_message "ERROR: ENFORCEMENT_POLICIES array is empty"
        return 0
    fi
    if [[ ! -f "$STATE_FILE" ]]; then return 0; fi

    for policy in "${ENFORCEMENT_POLICIES[@]}"; do
        local needs_action
        needs_action=$(/usr/libexec/PlistBuddy -c "Print :${policy}:needs_action" "$STATE_FILE" 2>/dev/null)
        if [[ "$needs_action" == "true" ]]; then return 0; fi
    done
    return 1
}

# Get list of specific policies that need action
get_policies_needing_action() {
    local needed_policies=()
    if [[ ! -f "$STATE_FILE" ]]; then echo "${needed_policies[@]}"; return 0; fi
    for policy in "${ENFORCEMENT_POLICIES[@]}"; do
        local needs_action
        needs_action=$(/usr/libexec/PlistBuddy -c "Print :${policy}:needs_action" "$STATE_FILE" 2>/dev/null)
        if [[ "$needs_action" == "true" ]]; then needed_policies+=("$policy"); fi
    done
    echo "${needed_policies[@]}"
}

# Check if any policy has reached deferral threshold
any_policy_over_threshold() {
    if [[ ! -f "$STATE_FILE" ]]; then return 1; fi
    for policy in "${ENFORCEMENT_POLICIES[@]}"; do
        local needs_action
        needs_action=$(/usr/libexec/PlistBuddy -c "Print :${policy}:needs_action" "$STATE_FILE" 2>/dev/null)
        if [[ "$needs_action" != "true" ]]; then continue; fi

        local count
        count=$(/usr/libexec/PlistBuddy -c "Print :${policy}:deferred_count" "$STATE_FILE" 2>/dev/null || echo 0)
        if [[ "$count" -ge "$DEFERRAL_THRESHOLD" ]]; then return 0; fi

        local first_detected
        first_detected=$(/usr/libexec/PlistBuddy -c "Print :${policy}:first_detected" "$STATE_FILE" 2>/dev/null || echo 0)
        if [[ "$first_detected" -gt 0 ]]; then
            local now=$(date +%s)
            local hours=$(( (now - first_detected) / 3600 ))
            if [[ "$hours" -ge "$MAX_DEFERRAL_HOURS" ]]; then return 0; fi
        fi
    done
    return 1
}

# Get human-readable list of issues
get_issue_summary() {
    local summary=""
    for policy in "${ENFORCEMENT_POLICIES[@]}"; do
        local needs_action
        needs_action=$(/usr/libexec/PlistBuddy -c "Print :${policy}:needs_action" "$STATE_FILE" 2>/dev/null)
        if [[ "$needs_action" == "true" ]]; then
            local reason
            reason=$(/usr/libexec/PlistBuddy -c "Print :${policy}:reason" "$STATE_FILE" 2>/dev/null || echo "Unknown")
            summary="${summary}• ${reason}\n"
        fi
    done
    echo -e "$summary"
}

get_issue_summary_line() {
    local summary=""
    for policy in "${ENFORCEMENT_POLICIES[@]}"; do
        local needs_action
        needs_action=$(/usr/libexec/PlistBuddy -c "Print :${policy}:needs_action" "$STATE_FILE" 2>/dev/null)
        if [[ "$needs_action" == "true" ]]; then
            local reason
            reason=$(/usr/libexec/PlistBuddy -c "Print :${policy}:reason" "$STATE_FILE" 2>/dev/null || echo "Unknown")
            if [[ -n "$summary" ]]; then summary="${summary}; "; fi
            summary="${summary}${policy}: ${reason}"
        fi
    done
    echo "$summary"
}

# Check if Cisco Secure Client is installed
check_csc_installed() {
    local csc_app_path="/Applications/Cisco/Cisco Secure Client.app"
    if [[ -d "$csc_app_path" ]]; then return 0; fi
    return 1
}

# Install Cisco Secure Client using enforcement policy
install_csc() {
    log_message "Installing Cisco Secure Client..."
    if [[ -z "$cscEnforcePolicy" ]]; then return 1; fi
    set_current_policy_event "$cscEnforcePolicy"
    if /usr/local/bin/jamf policy -event "$cscEnforcePolicy"; then
        sleep 5
        check_csc_installed && return 0
    fi
    return 1
}

# Disconnect VPN using Cisco Secure Client binary
disconnect_vpn() {
    log_message "Attempting to disconnect VPN..."
    local vpn_binary="/opt/cisco/secureclient/bin/vpn"
    if [[ ! -x "$vpn_binary" ]]; then return 1; fi
    
    local vpn_state=$("$vpn_binary" state 2>/dev/null)
    if ! echo "$vpn_state" | grep -q "state: Connected"; then return 0; fi
    
    "$vpn_binary" disconnect 2>/dev/null
    local timeout=15
    local counter=0
    while [[ $counter -lt $timeout ]]; do
        if ! "$vpn_binary" state 2>/dev/null | grep -q "state: Connected"; then return 0; fi
        sleep 1
        ((counter++))
    done
    return 1
}

# Run targeted enforcement policies based on specific issues
run_enforcement_policies() {
    local issues_needing_action
    read -r -a issues_needing_action <<< "$(get_policies_needing_action)"
    local policies_to_run=("${issues_needing_action[@]}")
    [[ ${#policies_to_run[@]} -eq 0 ]] && policies_to_run=("${ENFORCEMENT_POLICIES[@]}")
    
    local all_success=true
    for event in "${policies_to_run[@]}"; do
        set_current_policy_event "$event"
        /usr/local/bin/jamf policy -event "$event" || all_success=false
        clear_current_policy_event
        sleep 30
    done
    [[ "$all_success" == true ]] && return 0 || return 1
}

# Run validation policies to detect current system state
run_validation_policies() {
    for event in "${ENFORCEMENT_POLICIES[@]}"; do
        set_current_policy_event "$event"
        /usr/local/bin/jamf policy -event "$event"
        clear_current_policy_event
    done
}

# Clear entire state file
clear_all_state() {
    if [[ -f "$STATE_FILE" ]]; then
        for policy in "${ENFORCEMENT_POLICIES[@]}"; do
            /usr/libexec/PlistBuddy -c "Delete :${policy}" "$STATE_FILE" 2>/dev/null
        done
    fi
}

# Prompt user with jamfHelper
prompt_user() {
    local prompt_type="${1:-pre_disconnect}"
    
    if [[ ! -x "$JAMF_HELPER" ]]; then
        log_message "ERROR: jamfHelper not found at $JAMF_HELPER"
        return 2
    fi
    
    local issues=$(get_issue_summary)
    local title=""
    local description=""
    local button1="OK"
    local button2=""

    case "$prompt_type" in
        pre_disconnect)
            title="Cisco Secure Client Update Required"
            description="A Cisco Secure Client update is required to maintain security compliance.

Issues detected:
${issues}

Your VPN connection will be temporarily disconnected to complete this update."
            button1="Proceed Now"
            button2="Defer"
            ;;
        remediation_success)
            title="Update Complete"
            description="Remediation completed successfully. You may reconnect to your VPN."
            ;;
        remediation_failed)
            title="Update Incomplete"
            description="Remediation did not complete successfully and will be attempted again later."
            ;;
    esac

    log_message "Displaying jamfHelper dialog"
    
    local helper_args=(
        -windowType utility
        -title "$title"
        -description "$description"
        -icon "$ICON"
        -button1 "$button1"
    )
    
    [[ -n "$button2" ]] && helper_args+=( -button2 "$button2" )

    local result
    result=$("$JAMF_HELPER" "${helper_args[@]}")
    local exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        log_message "User clicked: $button1"
        echo "Proceed Now"
        return 0
    elif [[ $exit_code -eq 2 ]]; then
        log_message "User clicked: $button2"
        echo "Defer"
        return 0
    else
        log_message "jamfHelper failed or was dismissed (Exit: $exit_code)"
        return 2
    fi
}

# Increment global deferral (for user-initiated deferrals)
increment_global_deferral() {
    /usr/libexec/PlistBuddy -c "Add :global dict" "$STATE_FILE" 2>/dev/null
    local count=$(/usr/libexec/PlistBuddy -c "Print :global:user_deferrals" "$STATE_FILE" 2>/dev/null || echo 0)
    ((count++))
    /usr/libexec/PlistBuddy -c "Set :global:user_deferrals ${count}" "$STATE_FILE" 2>/dev/null || \
        /usr/libexec/PlistBuddy -c "Add :global:user_deferrals integer ${count}" "$STATE_FILE"
    /usr/libexec/PlistBuddy -c "Set :global:last_defer_time $(date +%s)" "$STATE_FILE" 2>/dev/null || \
        /usr/libexec/PlistBuddy -c "Add :global:last_defer_time integer $(date +%s)" "$STATE_FILE"
    log_message "User deferred update (total user deferrals: ${count})"
}

# Main orchestrator logic
main() {
    log_message "Orchestrator started"

    if [[ ${#ENFORCEMENT_POLICIES[@]} -eq 0 ]]; then
        log_message "ERROR: No enforcement policy triggers configured"
        exit 1
    fi

    if [[ ! -f "$STATE_FILE" ]]; then
        init_state_file
        if ! check_csc_installed; then
            install_csc || exit 1
        fi
        run_validation_policies
        exit 0
    fi
    
    init_state_file
    run_validation_policies
    
    if ! any_policy_needs_action; then
        log_message "Device is compliant"
        clear_all_state
        exit 0
    fi
    
    if ! any_policy_over_threshold; then
        log_message "Deferral threshold not yet reached"
        exit 0
    fi

    # Check current VPN state
    local vpn_currently_connected=false
    if [[ -x "/opt/cisco/secureclient/bin/vpn" ]]; then
        if "/opt/cisco/secureclient/bin/vpn" state 2>/dev/null | grep -q "state: Connected"; then
            vpn_currently_connected=true
        fi
    fi

    if [[ "$vpn_currently_connected" == true ]]; then
        local user_response=$(prompt_user "pre_disconnect")
        if [[ "$user_response" == "Defer" ]]; then
            increment_global_deferral
            exit 0
        elif [[ "$user_response" != "Proceed Now" ]]; then
            exit 1
        fi
    fi

    if disconnect_vpn; then
        if run_enforcement_policies; then
            run_validation_policies
            if ! any_policy_needs_action; then
                clear_all_state
                prompt_user "remediation_success"
                exit 0
            fi
        fi
    fi

    prompt_user "remediation_failed"
    exit 1
}

main "$@"
