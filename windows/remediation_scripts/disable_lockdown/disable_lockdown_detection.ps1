# =============================================================================
# Script:   disable_lockdown_detection.ps1
# Purpose:  Detects whether tamper resistance controls applied by the lockdown
#           script are currently active on Cisco Secure Client modules and Duo
#           Desktop components on Windows endpoints. Used by Microsoft Intune
#           as the detection script in the CSC Disable Lockdown remediation
#           script pair.
#
# Overview:
#   This script is the detection counterpart to disable_lockdown_remediation.ps1
#   and evaluates whether the lockdown controls applied by the lockdown script
#   are still present across three surfaces, reporting its findings as a
#   compressed JSON object before exiting with the appropriate code:
#
#     1. SCM-level descriptor: Compares the current SCM-level SDDL of each
#        present service against the known lockdown descriptor. A match
#        indicates the lockdown is still active on that service.
#     2. Registry ACL: Compares the current registry ACL of each present
#        service key under HKLM\SYSTEM\CurrentControlSet\Services against
#        the known lockdown descriptor. All services share the same lockdown
#        registry SDDL for detection purposes — the registrySddlKey property
#        is only relevant during restoration in the remediation script.
#     3. Uninstall key state: Checks each Cisco Secure Client and Duo Desktop
#        uninstall registry entry for two conditions:
#          - systemComponentSet: Whether the SystemComponent flag is present,
#            which hides the module from Add or Remove Programs.
#          - isLocked: Whether the lockdown ACL is still applied to the
#            uninstall key, which prevents the SystemComponent flag and other
#            values from being modified.
#
#   Unlike the lockdown_detection.ps1 script, which exits with code 1 when
#   lockdown controls are absent, this script exits with code 1 when lockdown
#   controls are present, as its purpose is to confirm that the lockdown has
#   been successfully removed. If any service SCM descriptor, registry ACL,
#   SystemComponent flag, or uninstall key ACL still matches the lockdown
#   configuration, the script exits with code 1, prompting Intune to execute
#   the paired disable lockdown remediation script.
#
#   WARNING: This script pair must never be assigned to the same device scope
#   as the CSC Lockdown remediation script pair in Intune. Doing so will create
#   a continuous enforcement conflict that undermines tamper resistance entirely.
#   Refer to the Enforcing Remediation Scripts section of the guide for full
#   details on safe scoping of this script pair.
#
# Usage:
#   Uploaded as the detection script of the CSC Disable Lockdown remediation
#   script pair in the Intune Remediations console. Can also be tested locally
#   using PsExec in the SYSTEM account context:
#   ./PsExec.exe -i -s powershell.exe -ExecutionPolicy Bypass -File "disable_lockdown_detection.ps1"; $LASTEXITCODE
#
# Configuration:
#   - The $services array at the top of the script defines which services are
#     evaluated for lockdown state. This list must match the services defined
#     in the paired disable_lockdown_remediation.ps1 script and should also
#     match the services defined in the lockdown scripts to ensure consistent
#     behavior across the full tamper resistance framework.
#   - If your environment does not use all of the modules covered in this
#     guide, remove the corresponding service entries from the array. If your
#     environment includes additional Secure Client modules beyond those
#     covered in this guide, add their service names to the array.
#   - To identify the service name for a given Cisco Secure Client or Duo
#     Desktop component, run the following command in PowerShell:
#
#       Get-Service | Where-Object { $_.DisplayName -like "*Cisco*" -or $_.DisplayName -like "*Duo*" } | Select-Object Name, DisplayName
#
# Exit Codes:
#   0 — No lockdown controls are detected. All SCM descriptors, registry ACLs,
#       SystemComponent flags, and uninstall key ACLs have been confirmed as
#       removed. Intune will take no action.
#   1 — One or more lockdown controls are still active. Intune will execute
#       the paired disable lockdown remediation script to remove them.
# =============================================================================

[CmdletBinding()]
param ()

# Defines the list of targeted services along with the SDDL key variant used during restoration
$services = @(
    [PSCustomObject]@{ "name" = "csc_vpnagent";                        "exists" = $null; "registrySddlKey" = "registry_sy" },
    [PSCustomObject]@{ "name" = "csc_umbrellaagent";                   "exists" = $null; "registrySddlKey" = "registry_sy" },
    [PSCustomObject]@{ "name" = "csc_swgagent";                        "exists" = $null; "registrySddlKey" = "registry_sy" },
    [PSCustomObject]@{ "name" = "csc_zta_agent";                       "exists" = $null; "registrySddlKey" = "registry_sy" },
    [PSCustomObject]@{ "name" = "acsock";                              "exists" = $null; "registrySddlKey" = "registry_ba" },
    [PSCustomObject]@{ "name" = "DuoCryptoService";                    "exists" = $null; "registrySddlKey" = "registry_ba" },
    [PSCustomObject]@{ "name" = "DuoTrustedPeerMessageBrokerService";  "exists" = $null; "registrySddlKey" = "registry_ba" },
    [PSCustomObject]@{ "name" = "DuoDesktopUpdateService";             "exists" = $null; "registrySddlKey" = "registry_ba" }
)

#[PSCustomObject]@{ "name" = "csc_nvmagent";         "exists" = $null; "registrySddlKey" = "registry_sy" },
#[PSCustomObject]@{ "name" = "CiscoCloudManagement"; "exists" = $null; "registrySddlKey" = "registry_sy" }
#[PSCustomObject]@{ "name" = "CiscoEVMService";       "exists" = $null; "registrySddlKey" = "registry_sy" }

# Defines the lockdown SDDL strings used as detection targets — detection triggers when these are present
# and passes when they are no longer found, confirming lockdown has been successfully removed
$securityDescriptor = [PSCustomObject]@{
    # Lockdown SCM-level SDDL — applied by the lockdown script via sc.exe sdset; restricts access to SYSTEM and Interactive Users
    "service"   = "D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCLCSWLOCRRC;;;IU)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)"
    # Lockdown registry SDDL — applied by the lockdown script via Set-Acl; denies write access to Administrators and standard users
    "registry"  = "O:SYG:SYD:PAI(D;;KW;;;BA)(D;;KW;;;BU)(A;;KA;;;SY)"
    # Lockdown uninstall SDDL — applied by the lockdown script via Set-Acl; same deny structure as the registry lockdown
    "uninstall" = "O:SYG:SYD:PAI(D;;KW;;;BA)(D;;KW;;;BU)(A;;KA;;;SY)"
}

# Probes each service to determine whether it is present on the system
$services | ForEach-Object {
    $service = $_
    try {
        Get-Service -Name $service.name -ErrorAction Stop | Out-Null
        $service.exists = $true
    }
    catch {
        $service.exists = $false
    }
}

# Collects the names of any services that were not found on the system
$missing_services = @()
$services | Where-Object { $_.exists -eq $false } | ForEach-Object {
    $missing_services += $_.name
}

# Retrieves the current SCM-level SDDL for each present service and flags it as locked if the lockdown descriptor is still applied
$securityDescriptors_services = @()
$services | Where-Object { $_.exists -eq $true } | ForEach-Object {
    $serviceName = $_.name
    $currentSddl = (& sc.exe sdshow $serviceName) | Where-Object { $_ -match "D:" }

    # isLocked = true indicates the lockdown SDDL is currently applied to this service
    $isLocked = ($currentSddl.Trim() -eq $securityDescriptor.service)

    $securityDescriptors_services += [PSCustomObject]@{
        "serviceName" = $serviceName
        "isLocked"    = $isLocked
    }
}

# Retrieves the current registry ACL for each present service key and flags it as locked if the lockdown descriptor is still applied
# All services share a single lockdown registry SDDL regardless of registrySddlKey — that property is only relevant during restoration
$securityDescriptors_registry = @()
$services | Where-Object { $_.exists -eq $true } | ForEach-Object {
    $serviceName = $_.name
    try {
        $acl = Get-Acl ("Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\{0}" -f $serviceName) -ErrorAction Stop |
               Select-Object -ExpandProperty Sddl

        # isLocked = true indicates the lockdown SDDL is currently applied to this registry key
        $isLocked = ($acl.Trim() -eq $securityDescriptor.registry)

        $securityDescriptors_registry += [PSCustomObject]@{
            "serviceName" = $serviceName
            "isLocked"    = $isLocked
        }
    }
    catch {
        # If the ACL cannot be read, the key is treated as locked to avoid a false-negative result
        $securityDescriptors_registry += [PSCustomObject]@{
            "serviceName" = $serviceName
            "isLocked"    = $true
        }
    }
}

# Checks each Cisco Secure Client and Duo uninstall entry for the presence of the SystemComponent flag and the lockdown uninstall ACL
$systemComponent_states = @()
$installedModules = @(
    Get-ItemProperty `
        HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*, `
        HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* `
        -ErrorAction SilentlyContinue |
    Where-Object { ($_.DisplayName -like "Cisco Secure Client*") -or ($_.DisplayName -like "*Duo*") }
)

$installedModules | ForEach-Object {
    $module                = $_
    $systemComponentValue  = $module.SystemComponent
    $isLocked              = $false

    try {
        $acl = Get-Acl $module.PSPath -ErrorAction Stop

        # isLocked = true indicates the lockdown uninstall SDDL is currently applied to this key
        $isLocked = ($acl.Sddl.Trim() -eq $securityDescriptor.uninstall)
    }
    catch {
        # If the ACL cannot be read, the key is treated as locked to avoid a false-negative result
        $isLocked = $true
    }

    $systemComponent_states += [PSCustomObject]@{
        "moduleName"         = $module.DisplayName
        "systemComponentSet" = ($systemComponentValue -eq 1)
        "isLocked"           = $isLocked
    }
}

# Emits all detection findings as a single compressed JSON object
Write-Host ([PSCustomObject]@{
    "missing"         = $missing_services
    "services"        = $securityDescriptors_services
    "registry"        = $securityDescriptors_registry
    "systemComponent" = $systemComponent_states
} | ConvertTo-Json -Compress)

# Returns exit code 1 if any service SCM-level SDDL still matches the lockdown descriptor
if ($securityDescriptors_services.isLocked -contains $true) {
    exit 1
}

# Returns exit code 1 if any service registry ACL still matches the lockdown descriptor
if ($securityDescriptors_registry.isLocked -contains $true) {
    exit 1
}

# Returns exit code 1 if the SystemComponent flag is still present on any Cisco Secure Client or Duo module
if ($systemComponent_states.systemComponentSet -contains $true) {
    exit 1
}

# Returns exit code 1 if any uninstall key ACL still matches the lockdown descriptor
if ($systemComponent_states.isLocked -contains $true) {
    exit 1
}

exit 0
