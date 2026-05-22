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

# Checks each Cisco Secure Client and Duo uninstall entry for the presence of the NoRemove flag and the lockdown uninstall ACL
$noRemove_states = @()
$installedModules = @(
    Get-ItemProperty `
        HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*, `
        HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* `
        -ErrorAction SilentlyContinue |
    Where-Object { ($_.DisplayName -like "Cisco Secure Client*") -or ($_.DisplayName -like "*Duo*") }
)

$installedModules | ForEach-Object {
    $module        = $_
    $noRemoveValue = $module.NoRemove
    $isLocked      = $false

    try {
        $acl = Get-Acl $module.PSPath -ErrorAction Stop

        # isLocked = true indicates the lockdown uninstall SDDL is currently applied to this key
        $isLocked = ($acl.Sddl.Trim() -eq $securityDescriptor.uninstall)
    }
    catch {
        # If the ACL cannot be read, the key is treated as locked to avoid a false-negative result
        $isLocked = $true
    }

    $noRemove_states += [PSCustomObject]@{
        "moduleName"  = $module.DisplayName
        "noRemoveSet" = ($noRemoveValue -eq 1)
        "isLocked"    = $isLocked
    }
}

# Emits all detection findings as a single compressed JSON object
Write-Host ([PSCustomObject]@{
    "missing"  = $missing_services
    "services" = $securityDescriptors_services
    "registry" = $securityDescriptors_registry
    "noRemove" = $noRemove_states
} | ConvertTo-Json -Compress)

# Returns exit code 1 if any service SCM-level SDDL still matches the lockdown descriptor
if ($securityDescriptors_services.isLocked -contains $true) {
    exit 1
}

# Returns exit code 1 if any service registry ACL still matches the lockdown descriptor
if ($securityDescriptors_registry.isLocked -contains $true) {
    exit 1
}

# Returns exit code 1 if the NoRemove flag is still present on any Cisco Secure Client or Duo module
if ($noRemove_states.noRemoveSet -contains $true) {
    exit 1
}

# Returns exit code 1 if any uninstall key ACL still matches the lockdown descriptor
if ($noRemove_states.isLocked -contains $true) {
    exit 1
}

exit 0
