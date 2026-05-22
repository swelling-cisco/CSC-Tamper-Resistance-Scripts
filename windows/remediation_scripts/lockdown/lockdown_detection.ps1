# =============================================================================
# Script:   lockdown_detection.ps1
# Purpose:  Detects whether tamper resistance controls are correctly applied
#           to all installed Cisco Secure Client modules and Duo Desktop
#           components on Windows endpoints. Used by Microsoft Intune as the
#           detection script in the CSC Lockdown remediation script pair.
#
# Overview:
#   This script evaluates the tamper resistance state of the endpoint across
#   four distinct surfaces and reports its findings as a compressed JSON object
#   before exiting with the appropriate code:
#
#     1. Service presence: Identifies any targeted services that are not found
#        on the endpoint and reports them in the "missing" array. Only services
#        that are present are evaluated in the remaining checks.
#     2. Service run state: Confirms that all present targeted services are
#        in a running state. Any service that is stopped or disabled is
#        reported as non-compliant.
#     3. SCM-level descriptor: Compares the current SCM-level SDDL of each
#        present service against the expected lockdown descriptor. Any service
#        whose descriptor does not match is reported as non-compliant.
#     4. Registry ACL: Compares the current registry ACL of each present
#        service key under HKLM\SYSTEM\CurrentControlSet\Services against
#        the expected lockdown descriptor. Any key whose ACL does not match
#        is reported as non-compliant.
#     5. SystemComponent flag: Confirms that the SystemComponent DWORD flag
#        is set on all Cisco Secure Client and Duo Desktop uninstall registry
#        entries, hiding them from Add or Remove Programs. Any entry where
#        the flag is absent is reported as non-compliant.
#
#   If any check identifies a non-compliant condition, the script exits with
#   code 1, prompting Intune to execute the paired lockdown remediation script
#   to restore the tamper resistance configuration.
#
# Usage:
#   Uploaded as the detection script of the CSC Lockdown remediation script
#   pair in the Intune Remediations console. Can also be tested locally using
#   PsExec in the SYSTEM account context:
#   ./PsExec.exe -i -s powershell.exe -ExecutionPolicy Bypass -File "lockdown_detection.ps1"; $LASTEXITCODE
#
# Configuration:
#   - The $services array at the top of the script defines which services are
#     evaluated for lockdown compliance. This list must match the services
#     defined in the paired lockdown_remediation.ps1 script to ensure
#     consistent detection and remediation behavior.
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
#   0 — All present services are running, all SCM-level and registry
#       descriptors match the expected lockdown configuration, and the
#       SystemComponent flag is set on all uninstall entries. Intune will
#       take no action.
#   1 — One or more checks have identified a non-compliant condition.
#       Intune will execute the paired lockdown remediation script to
#       restore the tamper resistance configuration.
# =============================================================================

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

# Checks each Cisco Secure Client and Duo uninstall entry to confirm the SystemComponent flag is set
$systemComponent_states = @()
$installedModules = @(
    Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue |
    Where-Object { ($_.DisplayName -like "Cisco Secure Client*") -or ($_.DisplayName -like "*Duo*") }
)
$installedModules | ForEach-Object {
    $module = $_
    $systemComponentValue = $module.SystemComponent
    $systemComponent_states += [PSCustomObject]@{
        "moduleName"         = $module.DisplayName
        "systemComponentSet" = ($systemComponentValue -eq 1)
    }
}

# Emits all detection findings as a single compressed JSON object
Write-Host ([PSCustomObject]@{
    "missing"         = $missing_services
    "states"          = $service_states
    "services"        = $securityDescriptors_services
    "registry"        = $securityDescriptors_registry
    "systemComponent" = $systemComponent_states
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

# Returns exit code 1 if the SystemComponent flag is absent on any Cisco Secure Client or Duo module
if ($systemComponent_states.systemComponentSet -contains $false) {
    exit 1
}

exit 0
