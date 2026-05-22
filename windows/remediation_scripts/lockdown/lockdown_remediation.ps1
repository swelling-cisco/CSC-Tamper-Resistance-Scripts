# =============================================================================
# Script:   lockdown_remediation.ps1
# Purpose:  Restores tamper resistance controls to all installed Cisco Secure
#           Client modules and Duo Desktop components on Windows endpoints when
#           configuration drift is detected. Used by Microsoft Intune as the
#           remediation script in the CSC Lockdown remediation script pair.
#
# Overview:
#   This script is functionally identical to lockdown.ps1 used during module
#   installation and applies the same layered set of tamper resistance controls
#   across four surfaces:
#
#     1. Service startup and state: Ensures all present targeted services are
#        set to Automatic startup and are in a running state before protections
#        are applied.
#     2. SCM-level descriptor: Applies a restrictive SDDL string to each
#        present targeted service via sc.exe sdset, limiting which accounts
#        can interact with the service through the Service Control Manager.
#     3. Registry ACL: Applies a deny-based ACL to each present service's
#        registry key under HKLM\SYSTEM\CurrentControlSet\Services, preventing
#        non-SYSTEM accounts from modifying the service configuration.
#     4. Uninstall key protection: Sets the SystemComponent flag on all Cisco
#        Secure Client and Duo Desktop uninstall registry entries to hide them
#        from Add or Remove Programs, and applies a protective ACL to each
#        entry to prevent unauthorized modification or removal.
#
#   This script is executed by Intune only when the paired lockdown detection
#   script exits with code 1, indicating that one or more tamper resistance
#   controls are missing or incorrect. It runs on the recurring schedule
#   configured for the remediation script pair, ensuring that any configuration
#   drift is automatically corrected within the next enforcement cycle.
#
# Usage:
#   Uploaded as the remediation script of the CSC Lockdown remediation script
#   pair in the Intune Remediations console. Can also be tested locally using
#   PsExec in the SYSTEM account context:
#   ./PsExec.exe -i -s powershell.exe -ExecutionPolicy Bypass -File "lockdown_remediation.ps1"; $LASTEXITCODE
#
# Configuration:
#   - The $services array at the top of the script defines which services are
#     targeted for lockdown remediation. This list must match the services
#     defined in the paired lockdown_detection.ps1 script to ensure consistent
#     detection and remediation behavior.
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
#   0 — All tamper resistance controls have been successfully applied or
#       were already in the correct state. Intune will record the remediation
#       as successful.
#   1 — Not explicitly returned by this script. Any failure during execution
#       will result in an unhandled termination that Intune will record as
#       a failed remediation.
# =============================================================================

[CmdletBinding()]
param ()

# Defines the list of Cisco Secure Client and Duo Desktop services targeted for lockdown
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

# Defines the target SDDL strings applied at the SCM, registry, and uninstall key levels
$securityDescriptor = [PSCustomObject]@{
    # Applied via sc.exe sdset — restricts SCM-level service access to SYSTEM and Interactive Users only
    "service"   = "D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCLCSWLOCRRC;;;IU)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)"
    # Applied via Set-Acl to the service registry key — denies write access to Administrators and standard users; grants full control to SYSTEM
    "registry"  = "O:SYG:SYD:PAI(D;;KW;;;BA)(D;;KW;;;BU)(A;;KA;;;SY)"
    # Applied via Set-Acl to the uninstall registry key — prevents modification of the SystemComponent flag by non-SYSTEM accounts
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

# Ensures all present services are set to Automatic startup and are in a running state
$service_remediation = @()
$services | Where-Object { $_.exists -eq $true } | ForEach-Object {
    $serviceName = $_.name
    try {
        $svc = Get-Service -Name $serviceName -ErrorAction Stop
        if ($svc.StartType -eq "Disabled") {
            Set-Service -Name $serviceName -StartupType Automatic -ErrorAction Stop
        }
        if ($svc.Status -ne "Running") {
            Start-Service -Name $serviceName -ErrorAction Stop
        }
        $service_remediation += [PSCustomObject]@{ "serviceName" = $serviceName; "success" = $true }
    }
    catch {
        $service_remediation += [PSCustomObject]@{ "serviceName" = $serviceName; "success" = $false }
    }
}

# Retrieves the current SCM-level SDDL for each present service and compares it against the target descriptor
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

# Retrieves the current registry ACL for each present service key and compares it against the target descriptor
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

# Applies the target SCM-level SDDL to any service whose descriptor does not match
$sddl_service_remediation = @()
$securityDescriptors_services | Where-Object { $_.correctDescriptor -eq $false } | ForEach-Object {
    $serviceName = $_.serviceName
    $result = & sc.exe sdset $serviceName $securityDescriptor.service
    if ($result -match "SUCCESS") {
        $sddl_service_remediation += [PSCustomObject]@{ "serviceName" = $serviceName; "success" = $true }
    }
    else {
        $sddl_service_remediation += [PSCustomObject]@{ "serviceName" = $serviceName; "success" = $false }
    }
}

# Applies the target registry ACL to any service key whose descriptor does not match
$sddl_registry_remediation = @()
$securityDescriptors_registry | Where-Object { $_.correctDescriptor -eq $false } | ForEach-Object {
    $serviceName = $_.serviceName
    $parentPath = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\{0}" -f $serviceName
    try {
        $acl = Get-Acl $parentPath -ErrorAction Stop
        $acl.SetSecurityDescriptorSddlForm($securityDescriptor.registry)
        Set-Acl -Path $parentPath -AclObject $acl -ErrorAction Stop
        $sddl_registry_remediation += [PSCustomObject]@{ "serviceName" = $serviceName; "success" = $true }
    }
    catch {
        $sddl_registry_remediation += [PSCustomObject]@{ "serviceName" = $serviceName; "success" = $false }
    }
}

# Locates all Cisco Secure Client and Duo uninstall registry entries, sets the SystemComponent flag, and applies a protective ACL
$systemComponent_remediation = @()
$installedModules = @(
    Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue |
    Where-Object { ($_.DisplayName -like "Cisco Secure Client*") -or ($_.DisplayName -like "*Duo*") }
)
$installedModules | ForEach-Object {
    $module = $_

    # Writes the SystemComponent DWORD value before applying the ACL to ensure the write is not blocked by subsequent deny rules
    New-ItemProperty -Path $module.PSPath -Name "SystemComponent" -Value 1 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null

    # Applies the protective ACL to lock down the uninstall key against modification
    try {
        $acl = Get-Acl $module.PSPath -ErrorAction Stop
        $acl.SetSecurityDescriptorSddlForm($securityDescriptor.uninstall)
        Set-Acl -Path $module.PSPath -AclObject $acl -ErrorAction Stop
        $systemComponent_remediation += [PSCustomObject]@{ "moduleName" = $module.DisplayName; "success" = $true }
    }
    catch {
        $systemComponent_remediation += [PSCustomObject]@{ "moduleName" = $module.DisplayName; "success" = $false }
    }
}

# Emits all remediation results as a single compressed JSON object
#Write-Host ([PSCustomObject]@{
#    "serviceStart"      = $service_remediation
#    "serviceSddl"       = $sddl_service_remediation
#    "registrySddl"      = $sddl_registry_remediation
#    "systemComponent"   = $systemComponent_remediation
#} | ConvertTo-Json -Compress)

exit 0
