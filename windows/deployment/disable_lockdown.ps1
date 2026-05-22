# =============================================================================
# Script:   disable_lockdown.ps1
# Purpose:  Removes tamper resistance controls applied by lockdown.ps1 from
#           all installed Cisco Secure Client modules and Duo Desktop components
#           on Windows endpoints, allowing install and uninstall operations to
#           proceed without being blocked by the active lockdown configuration.
#
# Overview:
#   This script is the counterpart to lockdown.ps1 and is responsible for
#   reversing the tamper resistance controls applied to the endpoint. When
#   executed, it restores permissive security descriptors and ACLs across
#   the same three surfaces targeted by the lockdown script:
#
#     1. SCM-level descriptor: Restores standard SCM access permissions for
#        SYSTEM, Administrators, Interactive Users, and Service accounts,
#        allowing the service to be stopped, started, and modified as needed
#        during the install or uninstall operation.
#     2. Registry ACL: Restores the original registry key permissions for each
#        targeted service key, removing the deny-based ACEs applied by the
#        lockdown script. Two variants of the restored SDDL are used depending
#        on the original owner of the key prior to lockdown — registry_sy for
#        SYSTEM-owned keys (Cisco Secure Client services) and registry_ba for
#        Administrators-owned keys (acsock and Duo Desktop services).
#     3. Uninstall key ACL: Restores inherited permissions on all Cisco Secure
#        Client and Duo Desktop uninstall registry entries by re-enabling ACL
#        inheritance and removing all explicit Deny ACEs applied by the lockdown
#        script. The SystemComponent flag is intentionally preserved so that
#        modules remain hidden from Add or Remove Programs during the install
#        or uninstall operation.
#
#   This script requires elevated token privileges (SeRestorePrivilege,
#   SeTakeOwnershipPrivilege, and SeTcbPrivilege) to take ownership of and
#   modify registry keys that were locked down by the lockdown script. These
#   privileges are enabled at runtime via an inline C# type definition.
#
#   This script is designed to be called as the first step of any Cisco Secure
#   Client module install or uninstall operation. The lockdown script should
#   always be executed immediately after the operation completes to restore
#   the full tamper resistance configuration.
#
# Usage:
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File "disable_lockdown.ps1"
#
# Configuration:
#   - The $services array at the top of the script defines which services are
#     targeted for lockdown removal. This list should match the services defined
#     in lockdown.ps1 to ensure consistent behavior across both scripts. Each
#     entry includes a registrySddlKey property that controls which restored
#     SDDL variant is applied to that service's registry key:
#       - "registry_sy" — used for SYSTEM-owned service keys (Cisco Secure
#         Client services: csc_vpnagent, csc_umbrellaagent, csc_swgagent,
#         csc_zta_agent)
#       - "registry_ba" — used for Administrators-owned service keys (acsock
#         and Duo Desktop services)
#   - To identify the service name for a given Cisco Secure Client or Duo
#     Desktop component, run the following command in PowerShell:
#
#       Get-Service | Where-Object { $_.DisplayName -like "*Cisco*" -or $_.DisplayName -like "*Duo*" } | Select-Object Name, DisplayName
#
# Requirements:
#   - Script must be executed in the SYSTEM account context, as is the case
#     when deployed via Intune or invoked by the module install/uninstall scripts.
# =============================================================================

[CmdletBinding()]
param ()

# Defines an inline C# type that exposes Win32 token privilege APIs used to elevate the script's effective permissions
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class TokenPrivilege {
    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    internal static extern bool AdjustTokenPrivileges(
        IntPtr htok, bool disall,
        ref TokPriv1Luid newst, int len,
        IntPtr prev, IntPtr relen);

    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    internal static extern bool OpenProcessToken(
        IntPtr h, int acc, ref IntPtr phtok);

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern bool LookupPrivilegeValue(
        string host, string name, ref long pluid);

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal struct TokPriv1Luid {
        public int Count;
        public long Luid;
        public int Attr;
    }

    internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
    internal const int TOKEN_QUERY = 0x00000008;
    internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;

    public static void Enable(string privilege) {
        IntPtr hproc = System.Diagnostics.Process.GetCurrentProcess().Handle;
        IntPtr htok = IntPtr.Zero;
        OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
        TokPriv1Luid tp;
        tp.Count = 1;
        tp.Luid  = 0;
        tp.Attr  = SE_PRIVILEGE_ENABLED;
        LookupPrivilegeValue(null, privilege, ref tp.Luid);
        AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
    }
}
"@

# Enables elevated privileges required to take ownership of registry keys and restore ACLs
[TokenPrivilege]::Enable("SeRestorePrivilege")
[TokenPrivilege]::Enable("SeTakeOwnershipPrivilege")
[TokenPrivilege]::Enable("SeTcbPrivilege")

# Defines the list of targeted services along with the SDDL key variant applicable to each
$services = @(
    [PSCustomObject]@{ "name" = "csc_vpnagent";                          "exists" = $null; "registrySddlKey" = "registry_sy" },
    [PSCustomObject]@{ "name" = "csc_umbrellaagent";                     "exists" = $null; "registrySddlKey" = "registry_sy" },
    [PSCustomObject]@{ "name" = "csc_swgagent";                          "exists" = $null; "registrySddlKey" = "registry_sy" },
    [PSCustomObject]@{ "name" = "csc_zta_agent";                         "exists" = $null; "registrySddlKey" = "registry_sy" },
    [PSCustomObject]@{ "name" = "acsock";                                "exists" = $null; "registrySddlKey" = "registry_ba" },
    [PSCustomObject]@{ "name" = "DuoCryptoService";                      "exists" = $null; "registrySddlKey" = "registry_ba" },
    [PSCustomObject]@{ "name" = "DuoTrustedPeerMessageBrokerService";    "exists" = $null; "registrySddlKey" = "registry_ba" },
    [PSCustomObject]@{ "name" = "DuoDesktopUpdateService";               "exists" = $null; "registrySddlKey" = "registry_ba" }
)

# Defines the restored SDDL strings applied at the SCM and registry levels after lockdown is removed
$securityDescriptor = [PSCustomObject]@{
    # Restores standard SCM access permissions for SYSTEM, Administrators, Interactive Users, and Service accounts
    "service"     = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)"
    # Restores registry key permissions for SYSTEM-owned service keys, granting inherited access to standard principals
    "registry_sy" = "O:SYG:SYD:AI(A;CIID;KR;;;BU)(A;CIID;KA;;;BA)(A;CIID;KA;;;SY)(A;CIIOID;KA;;;CO)(A;CIID;KR;;;AC)(A;CIID;KR;;;S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681)"
    # Restores registry key permissions for Administrators-owned service keys, granting inherited access to standard principals
    "registry_ba" = "O:BAG:SYD:AI(A;CIID;KR;;;BU)(A;CIID;KA;;;BA)(A;CIID;KA;;;SY)(A;CIIOID;KA;;;CO)(A;CIID;KR;;;AC)(A;CIID;KR;;;S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681)"
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

# Retrieves the current SCM-level SDDL for each present service and compares it against the restored target descriptor
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

# Applies the restored SCM-level SDDL to any service whose descriptor does not match
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

# Retrieves the current registry ACL for each present service key and compares it against the applicable restored descriptor
$securityDescriptors_registry = @()
$services | Where-Object { $_.exists -eq $true } | ForEach-Object {
    $serviceName   = $_.name
    $expectedSddl  = $securityDescriptor.($_.registrySddlKey)
    try {
        $acl = Get-Acl ("Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\{0}" -f $serviceName) -ErrorAction Stop |
               Select-Object -ExpandProperty Sddl
        if ($acl.Trim() -ne $expectedSddl) {
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

# Applies the restored registry ACL to any service key whose descriptor does not match
$sddl_registry_remediation = @()
$securityDescriptors_registry | Where-Object { $_.correctDescriptor -eq $false } | ForEach-Object {
    $serviceName  = $_.serviceName
    $parentPath   = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\{0}" -f $serviceName
    $expectedSddl = $securityDescriptor.($services | Where-Object { $_.name -eq $serviceName } | Select-Object -ExpandProperty registrySddlKey)
    try {
        $acl = Get-Acl $parentPath -ErrorAction Stop
        $acl.SetSecurityDescriptorSddlForm($expectedSddl)
        Set-Acl -Path $parentPath -AclObject $acl -ErrorAction Stop
        $sddl_registry_remediation += [PSCustomObject]@{ "serviceName" = $serviceName; "success" = $true }
    }
    catch {
        $sddl_registry_remediation += [PSCustomObject]@{ "serviceName" = $serviceName; "success" = $false }
    }
}

# Locates all Cisco Secure Client and Duo uninstall registry entries and restores their ACLs, preserving the SystemComponent flag
$systemComponent_remediation = @()
$installedModules = @(
    Get-ItemProperty `
        HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*, `
        HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* `
        -ErrorAction SilentlyContinue |
    Where-Object { ($_.DisplayName -like "Cisco Secure Client*") -or ($_.DisplayName -like "*Duo*") }
)

$installedModules | ForEach-Object {
    $module      = $_
    $aclRestored = $false

    try {
        # Converts the PowerShell PSDrive path to a raw registry path compatible with the .NET registry API
        $registryPath = $module.PSPath -replace "Microsoft\.PowerShell\.Core\\Registry::HKEY_LOCAL_MACHINE\\", ""

        # Opens the key with TakeOwnership rights and transfers ownership to BUILTIN\Administrators,
        # which is required to subsequently acquire ChangePermissions access when SYSTEM owns the key
        $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
            $registryPath,
            [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
            [System.Security.AccessControl.RegistryRights]::TakeOwnership
        )

        if ($null -ne $key) {
            $ownerAcl = $key.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Owner)
            # Set owner to BUILTIN\Administrators so subsequent ChangePermissions call succeeds
            $adminSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
            $ownerAcl.SetOwner($adminSid)
            $key.SetAccessControl($ownerAcl)
            $key.Close()
        }

        # Re-opens the key with ChangePermissions rights to strip lockdown-inserted Deny ACEs
        # and re-enables inheritance so permissions are cleanly derived from the parent key
        $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
            $registryPath,
            [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
            [System.Security.AccessControl.RegistryRights]::ChangePermissions
        )

        if ($null -ne $key) {
            $acl = $key.GetAccessControl()

            # Re-enables ACL inheritance from the parent key while preserving existing allow rules during the transition
            $acl.SetAccessRuleProtection($false, $true)

            # Removes all explicit Deny ACEs that were applied by the lockdown script
            $acl.Access |
                Where-Object { $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny } |
                ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }

            $key.SetAccessControl($acl)
            $key.Close()
            $aclRestored = $true
        }
    }
    catch {
        $aclRestored = $false
    }

    $systemComponent_remediation += [PSCustomObject]@{
        "moduleName"  = $module.DisplayName
        "aclRestored" = $aclRestored
    }
}

# Emits all remediation results as a single compressed JSON object
#Write-Host ([PSCustomObject]@{
#    "serviceSddl"      = $sddl_service_remediation
#    "registrySddl"     = $sddl_registry_remediation
#    "systemComponent"  = $systemComponent_remediation
#} | ConvertTo-Json -Compress)

exit 0
