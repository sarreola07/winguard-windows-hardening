# WinGuard: Windows 11 Hardening Tool

A PowerShell tool that audits a Windows 11 machine against a slice of the **Microsoft Security Baseline**, adds **advanced hardening controls** that go beyond the baseline, and can optionally apply the fixes and prove they worked with a before-and-after report.

Built for IS2083 Advanced Scripting (Lab 2) at UTSA.

## Features

- **Two modes.** `Audit` (the default) only reads settings. `Apply` audits, fixes what it safely can, then audits again.
- **15 controls** in two labeled groups (listed below).
- **Weighted security score** from 0 to 100, rated `STRONG` (85+), `MODERATE` (60+), or `NEEDS WORK`.
- **Timestamped text report** saved in `%USERPROFILE%\WinGuard_reports\`. Apply mode writes BEFORE, AFTER, and "Applying hardening" sections.
- **System Restore point** created before any change is made in Apply mode.
- **Start and completion pop-ups** that show the tool name and the score.

## Controls

### Microsoft Security Baseline

| Control | Checks | Fix |
|---|---|---|
| SMBv1 disabled | `EnableSMB1Protocol` is `$false` | `Set-SmbServerConfiguration -EnableSMB1Protocol $false` |
| SMB server signing required | `RequireSecuritySignature` is `$true` | `Set-SmbServerConfiguration -RequireSecuritySignature $true` |
| NTLM hardened | `Lsa\LmCompatibilityLevel` = 5 (NTLMv2 only) | Set the registry value to 5 |
| UAC enabled | `Policies\System\EnableLUA` = 1 | Set the registry value to 1 (reboot needed) |
| Minimum password length ≥ 14 | Parses `net accounts` | `net accounts /minpwlen:14` |
| Account lockout threshold 1–10 | Parses `net accounts` | `net accounts /lockoutthreshold:10` |
| Firewall on for all profiles | `Get-NetFirewallProfile` | `Set-NetFirewallProfile -Enabled True` |
| Defender real-time protection | `DisableRealtimeMonitoring` is `$false` | `Set-MpPreference -DisableRealtimeMonitoring $false` |
| Guest account disabled | `Get-LocalUser Guest` | `Disable-LocalUser Guest` |
| RDP requires NLA | `RDP-Tcp\UserAuthentication` = 1 | Set the registry value to 1 |

### Advanced hardening (beyond the baseline)

| Control | Checks | Fix |
|---|---|---|
| Defender PUA protection | `PUAProtection` = 1 | `Set-MpPreference -PUAProtection 1` |
| ASR: block Office child processes | Rule `D4F940AB-401B-4EFC-AADC-AD5F3C50688A` has action 1 | `Add-MpPreference` with the ASR rule |
| PowerShell script block logging | `ScriptBlockLogging\EnableScriptBlockLogging` = 1 | Create the policy key and set it to 1 |
| LSA protection (RunAsPPL) | `Lsa\RunAsPPL` = 1 | Set the registry value to 1 (reboot needed) |
| BitLocker on system drive | `Get-BitLockerVolume` shows `ProtectionStatus` is `On` | **Audit only.** Run `manage-bde -on C:` yourself |

## Requirements

- Windows 11. Enterprise Evaluation is recommended, because BitLocker and LSA protection need Enterprise or Pro.
- Windows PowerShell 5.1 (built in) or PowerShell 7.
- An **elevated** (Run as administrator) PowerShell. Audit still runs without elevation, but some checks fail, and Apply mode refuses to run.

## Usage

```powershell
# Allow local scripts for your account (one time)
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned

# Audit only; changes nothing
.\Harden-Windows.ps1

# Audit, remediate, re-audit (writes a before/after report)
.\Harden-Windows.ps1 -Mode Apply

# Open the newest report
notepad (Get-ChildItem "$env:USERPROFILE\*_reports\*.txt" | Sort-Object LastWriteTime | Select-Object -Last 1).FullName
```

## Sample report

[`sample-report.txt`](sample-report.txt) is a real before-and-after report from an Apply run on the lab VM.

## ⚠️ Safety

**Only run Apply mode on a test VM that you own and have snapshotted.** It changes real security settings, including password and lockout policy, NTLM level, SMB, RDP, and Defender. Some of these can lock out accounts or break connections to older systems. Apply mode creates a System Restore point first, but a VM snapshot is the reliable way to undo.

Tamper Protection in Windows Security can silently block `Set-MpPreference` changes. Turn it off while you test.

## Adding a control

Every control is one `New-Check` call:

```powershell
New-Check $BASELINE 'Control name' {
    # TEST: read the setting, return Pass + Detail
    @{ Pass = <bool>; Detail = '<what was found>' }
} {
    # REMEDIATE: fix it (or pass $null to make the control audit only)
} 10   # weight toward the score
```

## References

- [Microsoft Security Compliance Toolkit](https://www.microsoft.com/en-us/download/details.aspx?id=55319)
- [Attack Surface Reduction rules reference](https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-reference)
- [Configure LSA protection](https://learn.microsoft.com/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
