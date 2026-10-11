# WDACDriverBouncer

`WDACDriverBouncer.ps1` extends Microsoft's vulnerable driver blocklist with known-bad driver hashes from LOLDrivers using Windows Defender Application Control (WDAC). Its primary purpose is to supplement Microsoft's periodically updated blocklist with additional LOLDrivers rules between Microsoft updates. The script prepares and installs the combined policy in Audit or Enforce mode, with an option to use Microsoft's blocklist alone.

## Requirements

- Windows 11 operating system.
- Internet access to download the selected policy sources.
- Windows PowerShell 5.1 with the `ConfigCI` module and `ConvertFrom-CIPolicy` command available.

## Usage

Open Windows PowerShell as administrator and change to the folder containing the script. Both `-Setup` and `-Mode` are required.

**Recommended: start with the LOLDrivers setup in Audit mode.** This includes Microsoft's blocklist plus LOLDrivers rules and lets you review potential driver blocks before enabling enforcement:

```powershell
.\WDACDriverBouncer.ps1 -Setup LivingOffTheLandDriversPolicy -Mode Audit
```

Reboot to apply the policy. Review Code Integrity events in Event Viewer under **Applications and Services Logs > Microsoft > Windows > CodeIntegrity > Operational** and check that required drivers remain compatible before enforcing.

Once you have reviewed the audit events and resolved any compatibility issues, switch the LOLDrivers setup to Enforce mode, then reboot:

```powershell
.\WDACDriverBouncer.ps1 -Setup LivingOffTheLandDriversPolicy -Mode Enforce
```

Enforcement can prevent required drivers from loading. Test in Audit mode first and have a recovery plan before using Enforce mode.

If you prefer Microsoft's blocklist only, use `-Setup DefaultWindowsDriverPolicy` with the same Audit-first workflow.

## Start in Audit mode and verify blocks

Deploy with `-Mode Audit` first, reboot, and exercise normal workloads. In **Event Viewer > Applications and Services Logs > Microsoft > Windows > CodeIntegrity > Operational**, event ID **3076** identifies files that would be blocked if the policy were enforced. Review affected drivers and resolve compatibility issues before switching to `-Mode Enforce` and rebooting again.

In Enforce mode, event ID **3077** records an actual policy block. For a matching known-bad driver, this confirms that Windows prevented that driver from loading, helping prevent its abuse in a Bring Your Own Vulnerable Driver (BYOVD) attack. Check the event's file path and policy details to confirm which driver and policy caused the block; the event alone does not prove an attack occurred.

**Example event ID 3076 — Audit mode (driver allowed to load):**

```text
Code Integrity determined that a process (System) attempted to load \Device\HarddiskVolume3\Users\DTMLLUAdminUser\Downloads\HWAuidoOs2Ec.sys that did not meet the Authenticode signing level requirements or violated code integrity policy (Policy ID:{c017f6d6-2021-4204-aa68-f5065969b65e}). However, due to code integrity auditing policy, the image was allowed to load.
```

**Example event ID 3077 — Enforce mode (driver blocked):**

```text
Code Integrity determined that a process (System) attempted to load \Device\HarddiskVolume3\Users\DTMLLUAdminUser\Downloads\HWAuidoOs2Ec.sys that did not meet the Authenticode signing level requirements or violated code integrity policy (Policy ID:{c017f6d6-2021-4204-aa68-f5065969b65e}).
```

## Options

| Parameter | Value | Behavior |
| --- | --- | --- |
| `-Setup` | `DefaultWindowsDriverPolicy` | Downloads a fresh Microsoft blocklist on every run. |
| `-Setup` | `LivingOffTheLandDriversPolicy` | Extends the local `DriverPolicy_Enforced.xml`, or downloads Microsoft's blocklist if that file is missing, using the current LOLDrivers feed. |
| `-Mode` | `Audit` | Configures this policy to log would-be blocks. Other enforced policies may still block drivers. |
| `-Mode` | `Enforce` | Configures this policy to block matching drivers. |

## Skipped Samples

The skipped-samples CSV is refreshed on each completed LOLDrivers feed scan, when no valid authenticode hashes are found. Skipped samples are not included in the rules as there are no valid signature.

## Sources

- [Microsoft Vulnerable Driver Blocklist](https://aka.ms/VulnerableDriverBlockList)
- [LOLDrivers JSON feed](https://www.loldrivers.io/api/drivers.json)
