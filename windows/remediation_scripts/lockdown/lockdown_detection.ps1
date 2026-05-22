[CmdletBinding()]
param ()

# Defines the list of Cisco Secure Client and Duo Desktop services targeted for lockdown detection
$services = @(
    [PSCustomObject]@{ "name" = "csc_vpnagent"; "exists" = $null },
    [PSCustomObject]@{ "name" = "csc_umbrellaagent"; "exists" = $null },
    [PSCustomObject]@{ "name" = "csc_swgagent"; "exists" = $null },
    [PSCustomObject]@{ "name" = "csc_zta_agent"; "exists" = $null },
    [PSCustomObject]@{ "name" = "acsock"; "exists" = $null },
    [PSCustomObject]@{ "name" = "DuoCryptoService"; "exists" = $null },
    [PSCustomObject]@{ "name" = "DuoTrustedPeerMessageBrokerService"; "exists" = $null },
    [PSCustomObject]@{ "name" = "DuoDesktopUpdateService"; "exists" = $null }
)

#[PSCustomObject]@{ "name" = "csc_nvmagent"; "exists" = $null }
#[PSCustomObject]@{ "name" = "CiscoCloudManagement"; "exists" = $null }
#[PSCustomObject]@{ "name" = "CiscoEVMService"; "exists" = $null }

# Defines the expected SDDL strings that confirm lockdown is correctly applied at the SCM and registry levels
$securityDescriptor = [PSCustomObject]@{
    # Checked via sc.exe sdshow — confirms SCM-level access is restricted to SYSTEM and Interactive Users
    "service"  = "D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCLCSWLOCRRC;;;IU)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)"
    # Checked via Get-Acl on the service registry key — confirms write access is denied to Administrators and standard users
    "registry" = "O:SYG:SYD:PAI(D;;KW;;;BA)(D;;KW;;;BU)(A;;KA;;;SY)"
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

# Retrieves the current run state of each present service
$service_states = @()
$services | Where-Object { $_.exists -eq $true } | ForEach-Object {
    $serviceName = $_.name
    $status = (Get-Service -Name $serviceName).Status
    $service_states += [PSCustomObject]@{
        "serviceName" = $serviceName
        "running"     = ($status -eq "Running")
        "status"      = $status.ToString()
    }
}

# Retrieves the current SCM-level SDDL for each present service and compares it against the expected lockdown descriptor
$securityDescriptors_services = @()
$services | Where-Object { $_.exists -eq $true } | ForEach-Object {
    $serviceName = $_.name
    $currentSddl = (& sc.exe sdshow $serviceName) | Where-Object { $_ -match "D:" }
    if ($currentSddl.Trim() -ne $securityDescriptor.service) {
        $securityDescriptors_services += [PSCustomObject]@{ "serviceName" = $serviceName; "correctDescriptor" = $false }
    }
    else {
        $securityDescriptors_services += [PSCustomObject]@{ "serviceName" = $serviceName; "correctDescriptor" = $true }
    }
}

# Retrieves the current registry ACL for each present service key and compares it against the expected lockdown descriptor
$securityDescriptors_registry = @()
$services | Where-Object { $_.exists -eq $true } | ForEach-Object {
    $serviceName = $_.name
    try {
        $acl = Get-Acl ("Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\{0}" -f $serviceName) -ErrorAction Stop | Select-Object -ExpandProperty Sddl
        if ($acl.Trim() -ne $securityDescriptor.registry) {
            $securityDescriptors_registry += [PSCustomObject]@{ "serviceName" = $serviceName; "correctDescriptor" = $false }
        }
        else {
            $securityDescriptors_registry += [PSCustomObject]@{ "serviceName" = $serviceName; "correctDescriptor" = $true }
        }
    }
    catch {
        $securityDescriptors_registry += [PSCustomObject]@{ "serviceName" = $serviceName; "correctDescriptor" = $false }
    }
}

# Checks each Cisco Secure Client and Duo uninstall entry to confirm the NoRemove flag is set
$noRemove_states = @()
$installedModules = @(
    Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue |
    Where-Object { ($_.DisplayName -like "Cisco Secure Client*") -or ($_.DisplayName -like "*Duo*") }
)
$installedModules | ForEach-Object {
    $module = $_
    $noRemoveValue = $module.NoRemove
    $noRemove_states += [PSCustomObject]@{
        "moduleName"  = $module.DisplayName
        "noRemoveSet" = ($noRemoveValue -eq 1)
    }
}

# Emits all detection findings as a single compressed JSON object
Write-Host ([PSCustomObject]@{
    "missing"  = $missing_services
    "states"   = $service_states
    "services" = $securityDescriptors_services
    "registry" = $securityDescriptors_registry
    "noRemove" = $noRemove_states
} | ConvertTo-Json -Compress)

# Returns exit code 1 if any present service is not in a running state
if ($service_states.running -contains $false) {
    exit 1
}

# Returns exit code 1 if any service SCM-level SDDL does not match the expected lockdown descriptor
if ($securityDescriptors_services.correctDescriptor -contains $false) {
    exit 1
}

# Returns exit code 1 if any service registry ACL does not match the expected lockdown descriptor
if ($securityDescriptors_registry.correctDescriptor -contains $false) {
    exit 1
}

# Returns exit code 1 if the NoRemove flag is absent on any Cisco Secure Client or Duo module
if ($noRemove_states.noRemoveSet -contains $false) {
    exit 1
}

exit 0
