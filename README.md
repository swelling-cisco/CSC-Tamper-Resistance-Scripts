# Cisco Secure Client Tamper Resistance – Intune and Jamf Pro Deployment Scripts

A collection of PowerShell and Bash scripts that implement tamper resistance
controls for Cisco Secure Client on Windows and macOS endpoints. These scripts
enforce the integrity of Secure Client module installations, service states, and
configuration files through Microsoft Intune on Windows and Jamf Pro on macOS,
providing automated detection, remediation, and recovery of unauthorized or
unintended changes to the Secure Client deployment.

## Use Case

Cisco Secure Client integrates VPN, Zero Trust Access (ZTA), and Umbrella
Roaming Security into a unified endpoint security agent. While these modules
provide robust protection, their effectiveness depends entirely on their ability
to remain active, correctly installed, and properly configured. Without
additional controls, a user or process with sufficient privileges can stop
services, modify configuration files, or remove the software entirely, silently
degrading the security posture of the device.

This repository provides the scripts and supporting documentation necessary to
implement a layered tamper resistance strategy for Cisco Secure Client on both
Windows and macOS, using the enterprise MDM platforms already present in most
corporate environments. On Windows, Microsoft Intune Win32 app deployments and
remediation script pairs enforce service descriptor hardening, registry ACL
restrictions, and configuration file integrity. On macOS, a coordinated set of
Jamf Pro enforcement scripts continuously validate installation health,
module version compliance, and configuration file integrity, with automated
remediation and user-aware deferral logic built into the framework.

The solution is designed to complement, not replace, a broader endpoint
hardening strategy. It materially improves resilience and reduces the window of
exposure when tampering occurs, but is most effective when deployed alongside
strong administrative access controls, application control policies, and
centralized monitoring.

## Technology Stack

- **Language:** PowerShell (Windows), Bash (macOS)
- **MDM Platforms:** Microsoft Intune (Windows), Jamf Pro (macOS)
- **Endpoint Security:** Cisco Secure Client (VPN, Umbrella, ZTA modules)
- **Headend:** Cisco Secure Access (platform-agnostic; compatible with ASA,
  FTD, and Umbrella headends)
- **Status:** 1.0

## Installation

### Prerequisites

Before deploying these scripts, ensure the following prerequisites are met:

**All Platforms**
- A valid Cisco Secure Access subscription
- Target devices enrolled in Microsoft Intune (Windows) or Jamf Pro (macOS)
- Access to the Cisco Secure Access dashboard to download the Secure Client
  pre-deployment package and module configuration files
- Administrative access to the Intune Admin Center or Jamf Pro console

**Windows**
- Microsoft Win32 Content Prep Tool downloaded from the
  [Microsoft GitHub repository](https://github.com/microsoft/Microsoft-Win32-Content-Prep-Tool)
- Microsoft Sysinternals PsTools suite for validation testing
- The correct Cisco Secure Client pre-deployment package for your target
  Windows architecture (x86/x64 or ARM64)

**macOS**
- Jamf Pro with sufficient device seats for all target endpoints
- Cisco Secure Client macOS pre-deployment package (.dmg)

### Clone the Repository

```bash
git clone https://github.com/swelling-cisco/CSC-Tamper-Resistance-Scripts.git
```

Navigate to the repository root:

```bash
cd CSC-Tamper-Resistance-Scripts
```

## Configuration

All scripts in this repository require environment-specific values to be
updated before deployment. The key configuration points for each script are
described below. Refer to the in-script comment block at the top of each file
for the full list of configurable variables and their expected values.

### Windows Scripts

| Script | Key Configuration |
|---|---|
| `vpn_module_install.ps1` | Update `$installerName` to match your target MSI filename |
| `umbrella_module_install.ps1` | Update `$installerName` to match your target MSI filename |
| `zta_module_install.ps1` | Update `$installerName` and optionally configure the ZTA enrollment JSON deployment path |
| `vpn_config_detection.ps1` | Update the expected SHA256 hash to match your VPN XML profile |
| `vpn_config_remediation.ps1` | Embed your organization's VPN XML profile content |
| `umbrella_config_detection.ps1` | Update the expected SHA256 hash to match your OrgInfo.json |
| `umbrella_config_remediation.ps1` | Embed your organization's OrgInfo.json content |
| `zta_config_detection.ps1` | Update the expected SHA256 hash to match your ZTA enrollment JSON |
| `zta_config_remediation.ps1` | Embed your organization's ZTA enrollment JSON content |

> **Important:** Before deploying the Windows configuration detection and remediation script
> pairs, calculate the SHA256 hash of each module configuration file and update
> the corresponding expected hash value in the detection script. Run the
> following command in PowerShell on a device where the correct configuration
> files have already been deployed:
> ```bash
> (Get-FileHash "C:\path\to\configfile" -Algorithm SHA256).Hash
> ```

---

### macOS Scripts

| Script | Key Configuration |
|---|---|
| `csc_choices.sh` | Set module `selected` attribute values to match your licensed modules |
| `csc_install.sh` | Update `pkgPath` to match your Jamf Pro package filename if it differs from the default |
| `csc_enforcement_orchestrator.sh` | Verify `STATE_FILE`, `DEFERRAL_THRESHOLD`, and `MAX_DEFERRAL_HOURS` match your requirements |
| `csc_module_enforcement.sh` | Verify `STATE_FILE`. update `scBinaries` array to match deployed modules; remove `csc_swgagent` if SWG is not enabled in your Secure Access organization |
| `csc_config_enforcement.sh` | Verify `STATE_FILE`, `DEFERRAL_THRESHOLD`, and `MAX_DEFERRAL_HOURS` are consistent with the orchestrator |
| `csc_write_vpn.sh` | Replace the embedded XML with your organization's VPN profile; update `xmlfile` filename to match |
| `csc_write_umbrella.sh` | Replace the embedded JSON with your organization's OrgInfo.json credentials |
| `csc_write_zta.sh` | Update `FILENAME` to your organization's enrollment JSON filename; replace the embedded JWT payload |

> **Important:** The `STATE_FILE` path must be identical across
> `csc_enforcement_orchestrator.sh`, `csc_module_enforcement.sh`, and
> `csc_config_enforcement.sh`. A mismatch in this path between any of
> the three scripts will break the shared compliance state coordination
> that the enforcement framework depends on.

> **Important:** After updating any write script (`csc_write_vpn.sh`,
> `csc_write_umbrella.sh`, or `csc_write_zta.sh`) with your
> organization's configuration content, recalculate the SHA256 hash of
> the resulting file on a test device and update the corresponding
> Configuration Enforcement policy parameter in Jamf Pro:
> ```bash
> shasum -a 256 /path/to/configfile | awk '{print $1}'
> ```


## Usage

Detailed step-by-step deployment instructions for both platforms are provided
in the accompanying guide. The following section summarizes the high-level
deployment workflow for each platform.

### Windows – Microsoft Intune

**1. Prepare the installer packages**

Download the Cisco Secure Client pre-deployment package from the Cisco Secure
Access dashboard and gather module configuration files (VPN XML profile,
OrgInfo.json, ZTA enrollment JSON). Copy the relevant files into the
platform-specific source folders alongside the installation scripts.

**2. Package the installers for Intune**

Use the Microsoft Win32 Content Prep Tool to package each module into an
`.intunewin` file:

```bash
.\IntuneWinAppUtil.exe -c VPN -s vpn_module_install.ps1 -o Output
.\IntuneWinAppUtil.exe -c Umbrella -s umbrella_module_install.ps1 -o Output
.\IntuneWinAppUtil.exe -c ZTA -s zta_module_install.ps1 -o Output
```

**3. Validate on a test device**

Use PsExec to simulate the Intune system account execution context and test
each install script before deploying to production:

```bash
cd C:\PSTools
.\PsExec.exe -i -s powershell.exe
```

From the system-context PowerShell window:

```powershell
.\vpn_module_install.ps1
```

**4. Deploy via Intune**

Upload each `.intunewin` package to Intune as a Win32 application, configure
the install and uninstall commands, assign the detection rule script, and set
the target assignment scope. Configure the Umbrella and ZTA modules with a
dependency on the VPN Core module.

**5. Deploy remediation script pairs**

Upload and configure each remediation script pair in Intune under
Devices > Manage Devices > Scripts and Remediations. Set the execution
frequency to your required interval.

> **Warning:** Do not assign the Disable Lockdown remediation script pair
> to the same device groups as the Lockdown script pair. Doing so will
> create a continuous enforcement conflict that undermines the tamper
> resistance configuration entirely.

---

### macOS – Jamf Pro

**1. Upload the Secure Client package**

Upload the Cisco Secure Client `.pkg` file to Jamf Pro under
Settings > Content Management > Packages.

**2. Create scripts in Jamf Pro**

Upload each script in the `macos/` directory to the Jamf Pro script library
under Settings > Content Management > Scripts. Configure the Priority and
Parameter Labels for each script as described in the in-script comment block.

**3. Configure write scripts**

Update `csc_write_vpn.sh`, `csc_write_umbrella.sh`, and `csc_write_zta.sh`
with your organization's configuration content before uploading. After
finalizing each script, calculate the SHA256 hash of the resulting output
file on a test device:

```bash
shasum -a 256 /opt/cisco/secureclient/vpn/profile/<ProfileName>.xml | awk '{print $1}'
shasum -a 256 /opt/cisco/secureclient/umbrella/OrgInfo.json | awk '{print $1}'
shasum -a 256 /opt/cisco/secureclient/zta/enrollment_choices/<OrgID>_ZTA_Enroll_Cert.json | awk '{print $1}'
```

**4. Create Jamf Pro policies**

Create a policy for each script with the appropriate custom event trigger,
execution frequency, and scope. The required policy settings for each script
are documented in the accompanying guide. The custom event trigger names used
in this guide are:

| Policy | Custom Event Trigger |
|---|---|
| CSC – Install Secure Client Package | `csc_install` |
| CSC – Deploy VPN Profile | `deploy_vpn_profile` |
| CSC – Deploy Umbrella Profile | `deploy_umbrella_profile` |
| CSC – Deploy ZTA Profile | `deploy_zta_profile` |
| CSC – Enforce VPN Config | `csc_enforce_vpn` |
| CSC – Enforce Umbrella Config | `csc_enforce_umbrella` |
| CSC – Enforce ZTA Config | `csc_enforce_zta` |
| CSC – Enforce Secure Client Modules | `csc_enforce_modules` |
| CSC – Orchestrator | `csc_orchestrate` (+ Recurring Check-in) |

> **Note:** These trigger names are examples. You may use different names
> in your environment, but they must be consistent across all policy
> configurations and script parameters. Any mismatch will prevent the
> enforcement framework from calling the correct policies during
> remediation.

**5. Deploy MDM configuration profiles**

Before or alongside the installer policy, deploy the required macOS
configuration profiles via Jamf Pro to pre-approve system extensions,
content filters, Privacy Preferences Policy Controls (PPPC), and managed
login items. Deploying these profiles after installation may result in macOS
presenting permission prompts to the user during enforcement-triggered
reinstallation.

**6. Validate on a test device**

Manually invoke the orchestrator on a scoped test device to confirm that all
modules install correctly and that the enforcement framework detects and
remediates compliance issues as expected:

```bash
sudo jamf policy -event csc_orchestrate
```

Inspect the shared enforcement state file to verify compliance tracking:

```bash
defaults read /Library/Application\ Support/SecureClientEnforcement/csc_enforcement_state.plist
```

## Related Resources

- [Cisco Secure Client Administrator Guide](https://www.cisco.com/c/en/us/support/security/anyconnect-secure-mobility-client/products-installation-and-configuration-guides-list.html)
- [Cisco Secure Access Documentation](https://docs.sse.cisco.com)
- [Cisco Secure Client Release Notes](https://www.cisco.com/c/en/us/support/security/anyconnect-secure-mobility-client/products-release-notes-list.html)
- [Microsoft Intune Win32 App Deployment](https://learn.microsoft.com/en-us/mem/intune/apps/apps-win32-app-management)
- [Microsoft Win32 Content Prep Tool](https://github.com/microsoft/Microsoft-Win32-Content-Prep-Tool)
- [Microsoft Sysinternals PsTools](https://learn.microsoft.com/en-us/sysinternals/downloads/pstools)
- [Jamf Pro Documentation](https://learn.jamf.com/bundle/jamf-pro-documentation-current/page/Jamf_Pro_Documentation.html)

## License

This code is licensed under the Cisco Sample Code License. See
[LICENSE](./LICENSE) for details.

## References

- [Cisco Secure Client Product Page](https://www.cisco.com/c/en/us/products/security/anyconnect-secure-mobility-client/index.html)
- [Microsoft Intune Documentation](https://learn.microsoft.com/en-us/mem/intune/)
- [Jamf Pro Documentation](https://learn.jamf.com)
- [Apple Platform Security Guide](https://support.apple.com/guide/security/welcome/web)
- [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/)
