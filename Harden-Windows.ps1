# Harden-Windows.ps1  (COMPLETED - all 13 TODOs implemented)
# IS2083 Advanced Scripting - Lab 2: Windows Hardening Tool
#
# Author: Sergio Arreola
#
# BEFORE YOU START
#   Save this file as  Harden-Windows.ps1  (remove "_STARTER" from the name).
#   Every command in the lab handout runs  .\Harden-Windows.ps1 , so the name
#   must match exactly.
#
# HOW THIS FILE MATCHES THE LAB HANDOUT
#   Handout Part A, Step 5 ......... run this file once as it is.
#   Handout Part B ................. build the controls in THIS file. Part B has
#                                    two tables:
#                                      "Microsoft Security Baseline controls"
#                                      "Advanced controls (beyond the baseline)"
#                                    Each TODO below names the table and the row
#                                    (the Control column) to use.
#   Handout Part C, Step 6 ......... run an audit.
#   Handout Part D, Step 7 ......... run  .\Harden-Windows.ps1 -Mode Apply
#   The TODOs are numbered 1 to 13 in this file only. Search for "TODO" to
#   find every control you still need to build.
#
# WHAT THIS FILE ALREADY DOES FOR YOU
#   - Two modes: Audit (read only, the default) and Apply (fixes what it safely can).
#   - A weighted security score with a STRONG / MODERATE / NEEDS WORK rating.
#   - A grouped report (Microsoft Security Baseline, then Advanced hardening),
#     saved as a timestamped .txt file in  C:\Users\<you>\<ToolName>_reports
#   - Start and completion pop-ups that show your tool name and score.
#   - Two finished controls you can copy: SMBv1 disabled and SMB server
#     signing required.
#
# HOW TO READ ONE CONTROL (a New-Check)
#   Every control has the same four parts, in this order:
#
#     New-Check $BASELINE 'Control name' {     # 1. category and name
#         ...read the setting...               # 2. TEST block: the first { }
#         @{ Pass = ...; Detail = ... }        #    returns Pass ($true or $false)
#     } {                                      #    and a Detail message
#         ...fix the setting...                # 3. REMEDIATE block: the second { }
#     } 10                                     # 4. weight (points toward the score)
#
#   In the TODO controls, the REMEDIATE block has not been written yet, so the
#   placeholder $null sits in its place. Look for this line:
#
#     } $null 10
#
#   The } closes the TEST block, $null is the empty REMEDIATE slot, and 10 is
#   the weight.
#
# HOW TO BUILD A TODO CONTROL
#   Here is what the finished SMB signing control below looked like as a TODO,
#   and what it looks like finished. Every TODO works the same way.
#
#   BEFORE (a TODO stub):
#     New-Check $BASELINE 'SMB server signing required' {
#         @{ Pass = $false; Detail = 'TODO: ...' }
#     } $null 10
#
#   AFTER (TEST block replaced, and $null swapped for a REMEDIATE block):
#     New-Check $BASELINE 'SMB server signing required' {
#         $c = Get-SmbServerConfiguration -ErrorAction Stop
#         @{ Pass = [bool]$c.RequireSecuritySignature; Detail = "RequireSecuritySignature=$($c.RequireSecuritySignature)" }
#     } {
#         Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
#     } 10
#
#   The TEST block uses the "Audit (read this)" column of the handout table.
#   The REMEDIATE block uses the "Fix (apply this)" column.
#   For the audit only control (BitLocker), keep $null.
#
#   After each control: save, run  .\Harden-Windows.ps1 , and confirm that
#   control now shows its real state.
#
# RUN IT
#   .\Harden-Windows.ps1                # audit only, changes nothing
#   .\Harden-Windows.ps1 -Mode Apply    # audit, fix, re-audit (practice VM only)

param(
    [ValidateSet('Audit','Apply')]
    [string]$Mode = 'Audit'
)

# ======================= SET YOUR TOOL NAME HERE =======================
$ToolName = 'WinGuard'
# =======================================================================

# Category labels used in the code and the report.
$BASELINE = 'Microsoft Security Baseline'
$ADVANCED = 'Advanced hardening'

# The list every New-Check call registers into.
$script:Checks = @()

# ---------- Helper: are we running as Administrator? (done for you) ----------
function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ---------- Helper: show a pop-up, fall back to the console (done for you) ----------
function Show-Popup {
    param([string]$Message, [string]$Title)
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        [void][System.Windows.Forms.MessageBox]::Show($Message, $Title)
    } catch {
        Write-Host ('[' + $Title + '] ' + $Message) -ForegroundColor Magenta
    }
}

# ---------- Helper: rate a score (done for you) ----------
function Get-Rating {
    param([int]$Score)
    if ($Score -ge 85)      { return 'STRONG' }
    elseif ($Score -ge 60)  { return 'MODERATE' }
    else                    { return 'NEEDS WORK' }
}

# ---------- Register one control (done for you) ----------
# Usage:  New-Check <Category> '<Name>' { Test returns @{Pass=..;Detail=..} } { Remediate } <Weight>
# Pass $null for the Remediate block to make a control audit only.
function New-Check {
    param(
        [string]$Category,
        [string]$Name,
        [scriptblock]$Test,
        [scriptblock]$Remediate,
        [int]$Weight = 10
    )
    $script:Checks += [pscustomobject]@{
        Category  = $Category
        Name      = $Name
        Test      = $Test
        Remediate = $Remediate
        Weight    = $Weight
    }
}

# =======================================================================
#  Microsoft Security Baseline controls  (category: $BASELINE)
# =======================================================================

# SMBv1 disabled  (DONE: finished example, copy this shape)
New-Check $BASELINE 'SMBv1 disabled' {                 # TEST block starts here
    $c = Get-SmbServerConfiguration -ErrorAction Stop
    @{ Pass = [bool](-not $c.EnableSMB1Protocol); Detail = "EnableSMB1Protocol=$($c.EnableSMB1Protocol)" }
} {                                                    # TEST ends, REMEDIATE starts
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
} 10                                                   # REMEDIATE ends, weight 10

# SMB server signing required  (DONE: the worked example in handout Part B)
New-Check $BASELINE 'SMB server signing required' {
    $c = Get-SmbServerConfiguration -ErrorAction Stop
    @{ Pass = [bool]$c.RequireSecuritySignature; Detail = "RequireSecuritySignature=$($c.RequireSecuritySignature)" }
} {
    Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
} 10

# TODO 1 of 13 (DONE): NTLM hardened. Handout Part B, Baseline table, row "NTLM hardened".
#   LmCompatibilityLevel 5 = send NTLMv2 only, refuse LM and NTLMv1.
#   The value is often missing on a new VM (Windows then behaves as level 3),
#   so -ErrorAction SilentlyContinue turns "missing" into a FAIL, not an error.
New-Check $BASELINE 'NTLM hardened (LmCompatibilityLevel = 5)' {
    $v = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -ErrorAction SilentlyContinue).LmCompatibilityLevel
    if ($null -eq $v) { $shown = 'not set (Windows default 3)' } else { $shown = $v }
    @{ Pass = ($v -eq 5); Detail = "LmCompatibilityLevel=$shown" }
} {
    Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -Value 5 -Type DWord -ErrorAction Stop
} 10

# TODO 2 of 13 (DONE): UAC enabled. Handout Part B, Baseline table, row "UAC enabled".
#   EnableLUA 1 = UAC on. Changing it needs a reboot (the engine notes this).
New-Check $BASELINE 'User Account Control (UAC) enabled' {
    $v = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA
    @{ Pass = ($v -eq 1); Detail = "EnableLUA=$v" }
} {
    Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1 -Type DWord -ErrorAction Stop
} 10

# TODO 3 of 13 (DONE): Minimum password length. Handout Part B, Baseline table, row "Min password length 14".
#   net accounts prints text lines; grab the 'Minimum password length' line and
#   read the number at the end of it.
New-Check $BASELINE 'Minimum password length 14 or more' {
    $line = @(net accounts | Where-Object { $_ -match 'Minimum password length' })[0]
    $len = 0
    if ($line -match '(\d+)\s*$') { $len = [int]$Matches[1] }
    @{ Pass = ($len -ge 14); Detail = "Minimum password length=$len" }
} {
    net accounts /minpwlen:14 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "net accounts /minpwlen:14 exited with code $LASTEXITCODE" }
} 10

# TODO 4 of 13 (DONE): Lockout threshold. Handout Part B, Baseline table, row "Lockout threshold 1..10".
#   Pass for 1 to 10. 'Never' has no number, so it stays 0 and fails.
New-Check $BASELINE 'Account lockout threshold 1 to 10' {
    $line = @(net accounts | Where-Object { $_ -match 'Lockout threshold' })[0]
    $n = 0
    if ($line -match '(\d+)\s*$') { $n = [int]$Matches[1] }
    if ($n -eq 0) { $shown = 'Never (0)' } else { $shown = $n }
    @{ Pass = ($n -ge 1 -and $n -le 10); Detail = "Lockout threshold=$shown" }
} {
    net accounts /lockoutthreshold:10 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "net accounts /lockoutthreshold:10 exited with code $LASTEXITCODE" }
} 10

# TODO 5 of 13 (DONE): Firewall. Handout Part B, Baseline table, row "Firewall all profiles".
#   .Enabled is a GpoBoolean (True / False / NotConfigured), not a plain bool,
#   so compare it as text: casting NotConfigured to [bool] would wrongly give $true.
New-Check $BASELINE 'Firewall enabled on all profiles' {
    $profiles = @(Get-NetFirewallProfile -ErrorAction Stop)
    $off = @($profiles | Where-Object { [string]$_.Enabled -ne 'True' })
    $detail = ($profiles | ForEach-Object { $_.Name + '=' + $_.Enabled }) -join ', '
    @{ Pass = ($profiles.Count -gt 0 -and $off.Count -eq 0); Detail = $detail }
} {
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -ErrorAction Stop
} 10

# TODO 6 of 13 (DONE): Defender real-time protection. Handout Part B, Baseline table, row "Defender real-time on".
#   If Tamper Protection is on, Windows may ignore Set-MpPreference; turn it off
#   in Windows Security while testing (see handout Troubleshooting).
New-Check $BASELINE 'Defender real-time protection on' {
    $p = Get-MpPreference -ErrorAction Stop
    @{ Pass = (-not $p.DisableRealtimeMonitoring); Detail = "DisableRealtimeMonitoring=$($p.DisableRealtimeMonitoring)" }
} {
    Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
} 10

# TODO 7 of 13 (DONE): Guest account. Handout Part B, Baseline table, row "Guest account disabled".
New-Check $BASELINE 'Guest account disabled' {
    $u = Get-LocalUser -Name Guest -ErrorAction Stop
    @{ Pass = (-not $u.Enabled); Detail = "Guest Enabled=$($u.Enabled)" }
} {
    Disable-LocalUser -Name Guest -ErrorAction Stop
} 10

# TODO 8 of 13 (DONE): RDP requires NLA. Handout Part B, Baseline table, row "RDP requires NLA".
#   UserAuthentication 1 = the client must authenticate before a session is created.
New-Check $BASELINE 'RDP requires Network Level Authentication' {
    $v = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -ErrorAction SilentlyContinue).UserAuthentication
    @{ Pass = ($v -eq 1); Detail = "UserAuthentication=$v" }
} {
    Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1 -Type DWord -ErrorAction Stop
} 10

# =======================================================================
#  Advanced controls (beyond the baseline)  (category: $ADVANCED)
# =======================================================================

# TODO 9 of 13 (DONE): Defender PUA protection. Handout Part B, Advanced table, row "Defender PUA protection".
#   PUAProtection: 0 = off, 1 = block, 2 = audit only.
New-Check $ADVANCED 'Defender PUA protection on' {
    $p = Get-MpPreference -ErrorAction Stop
    @{ Pass = ($p.PUAProtection -eq 1); Detail = "PUAProtection=$($p.PUAProtection)" }
} {
    Set-MpPreference -PUAProtection 1 -ErrorAction Stop
} 8

# TODO 10 of 13 (DONE): ASR rule. Handout Part B, Advanced table, row "ASR: block Office child procs".
#   The Ids list and the Actions list line up by position. Find the rule id's
#   position in Ids, then check the same position in Actions is 1 (Block).
New-Check $ADVANCED 'ASR: block Office child processes' {
    $ruleId  = 'D4F940AB-401B-4EFC-AADC-AD5F3C50688A'
    $p       = Get-MpPreference -ErrorAction Stop
    $ids     = @($p.AttackSurfaceReductionRules_Ids)
    $actions = @($p.AttackSurfaceReductionRules_Actions)
    $action  = $null
    for ($i = 0; $i -lt $ids.Count; $i++) {
        if ($ids[$i] -eq $ruleId) { $action = $actions[$i] }   # -eq on strings ignores case
    }
    if ($null -eq $action) { $shown = 'rule not configured' } else { $shown = "action=$action" }
    @{ Pass = ($action -eq 1); Detail = "ASR $ruleId $shown" }
} {
    Add-MpPreference -AttackSurfaceReductionRules_Ids 'D4F940AB-401B-4EFC-AADC-AD5F3C50688A' -AttackSurfaceReductionRules_Actions Enabled -ErrorAction Stop
} 8

# TODO 11 of 13 (DONE): Script block logging. Handout Part B, Advanced table, row "Script block logging".
#   The policy key does not exist on a new VM, so the fix creates it first.
New-Check $ADVANCED 'PowerShell script block logging on' {
    $v = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue).EnableScriptBlockLogging
    if ($null -eq $v) { $shown = 'not set' } else { $shown = $v }
    @{ Pass = ($v -eq 1); Detail = "EnableScriptBlockLogging=$shown" }
} {
    $key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    New-Item -Path $key -Force | Out-Null
    Set-ItemProperty -Path $key -Name EnableScriptBlockLogging -Value 1 -Type DWord -ErrorAction Stop
} 8

# TODO 12 of 13 (DONE): LSA protection. Handout Part B, Advanced table, row "LSA protection (RunAsPPL)".
#   RunAsPPL 1 runs LSASS as a protected process so tools cannot dump its memory.
#   Takes effect after a reboot (the engine notes this).
New-Check $ADVANCED 'LSA protection (RunAsPPL) on' {
    $v = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -ErrorAction SilentlyContinue).RunAsPPL
    if ($null -eq $v) { $shown = 'not set' } else { $shown = $v }
    @{ Pass = ($v -eq 1); Detail = "RunAsPPL=$shown" }
} {
    Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -Value 1 -Type DWord -ErrorAction Stop
} 8

# TODO 13 of 13 (DONE): BitLocker. Handout Part B, Advanced table, row "BitLocker on system drive".
#   AUDIT ONLY: Remediate stays $null. Turn it on yourself with  manage-bde -on $env:SystemDrive
#   If BitLocker is unavailable in the VM, the engine catches the error and reports FAIL.
New-Check $ADVANCED 'BitLocker on system drive' {
    $vol = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
    @{ Pass = ([string]$vol.ProtectionStatus -eq 'On'); Detail = "ProtectionStatus=$($vol.ProtectionStatus), VolumeStatus=$($vol.VolumeStatus) (audit only)" }
} $null 6

# =======================================================================
#  Engine (done for you): audit, apply, report
# =======================================================================

# Run every check, print a grouped report, compute the weighted score.
function Invoke-Audit {
    param([string]$Label = '')

    $results = @()
    foreach ($c in $script:Checks) {
        try {
            $r = & $c.Test
        } catch {
            $r = @{ Pass = $false; Detail = ('error: ' + $_.Exception.Message) }
        }
        $results += [pscustomobject]@{
            Category = $c.Category
            Name     = $c.Name
            Pass     = [bool]$r.Pass
            Detail   = [string]$r.Detail
            Weight   = [int]$c.Weight
        }
    }

    $total  = ($script:Checks | Measure-Object -Property Weight -Sum).Sum
    $earned = (@($results | Where-Object { $_.Pass }) | Measure-Object -Property Weight -Sum).Sum
    if (-not $total)  { $total  = 1 }
    if (-not $earned) { $earned = 0 }
    $score  = [math]::Round(($earned / $total) * 100)
    $rating = Get-Rating -Score $score

    $header = '=== Windows Security Audit ==='
    if ($Label) { $header = $header + '  [' + $Label + ']' }
    Write-Host ''
    Write-Host $header -ForegroundColor Cyan

    foreach ($cat in @($BASELINE, $ADVANCED)) {
        $catResults = @($results | Where-Object { $_.Category -eq $cat })
        if ($catResults.Count -eq 0) { continue }
        $catPass = @($catResults | Where-Object { $_.Pass }).Count
        Write-Host ''
        Write-Host ('-- ' + $cat + '  (' + $catPass + ' of ' + $catResults.Count + ' passing) --') -ForegroundColor White
        foreach ($x in $catResults) {
            if ($x.Pass) {
                Write-Host ('  [PASS] ' + $x.Name) -ForegroundColor Green
            } else {
                Write-Host ('  [FAIL] ' + $x.Name + '  ->  ' + $x.Detail) -ForegroundColor Red
            }
        }
    }

    Write-Host ''
    Write-Host ('Security score: ' + $score + ' / 100   (' + $rating + ')') -ForegroundColor Yellow
    Write-Host ''

    return [pscustomobject]@{
        Label   = $Label
        Results = $results
        Earned  = $earned
        Total   = $total
        Score   = $score
        Rating  = $rating
    }
}

# Make a restore point, then remediate every failing control that has a fix.
function Invoke-Apply {
    $actions = @()

    try {
        Enable-ComputerRestore -Drive 'C:\' -ErrorAction SilentlyContinue
        Checkpoint-Computer -Description ('Before ' + $ToolName + ' hardening') -RestorePointType MODIFY_SETTINGS -ErrorAction Stop
        $actions += 'Created a System Restore Point (your undo button).'
    } catch {
        $actions += 'Could not create a restore point (it may be off or rate limited). Continuing.'
    }

    foreach ($c in $script:Checks) {
        if ($null -eq $c.Remediate) { continue }        # audit-only control
        try { $r = & $c.Test } catch { $r = @{ Pass = $false } }
        if ([bool]$r.Pass) { continue }                 # already passing
        try {
            & $c.Remediate
            $note = 'Remediated: ' + $c.Name
            if ($c.Name -match 'UAC' -or $c.Name -match 'LSA') {
                $note = $note + '   (reboot required to take effect)'
            }
            $actions += $note
        } catch {
            $actions += ('Remediation failed: ' + $c.Name + '  ->  ' + $_.Exception.Message)
        }
    }

    return $actions
}

# Write a timestamped, grouped report and return its path.
function Write-Report {
    param([array]$Summaries, [array]$Actions)

    $dir = Join-Path $env:USERPROFILE ($ToolName + '_reports')
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $path  = Join-Path $dir ($ToolName + '_report_' + $stamp + '.txt')

    $lines = @()
    $lines += ($ToolName + ' Security Report')
    $lines += ('Generated: ' + (Get-Date))
    $lines += ('Computer:  ' + $env:COMPUTERNAME)
    $lines += ''

    foreach ($s in $Summaries) {
        $title = 'AUDIT'
        if ($s.Label) { $title = $s.Label }
        $lines += ('===== ' + $title + ' =====')
        foreach ($cat in @($BASELINE, $ADVANCED)) {
            $cr = @($s.Results | Where-Object { $_.Category -eq $cat })
            if ($cr.Count -eq 0) { continue }
            $cp = @($cr | Where-Object { $_.Pass }).Count
            $lines += ''
            $lines += ('-- ' + $cat + '  (' + $cp + ' of ' + $cr.Count + ' passing) --')
            foreach ($x in $cr) {
                $flag = '[FAIL]'
                if ($x.Pass) { $flag = '[PASS]' }
                $lines += ('  ' + $flag + ' ' + $x.Name + '  ->  ' + $x.Detail)
            }
        }
        $lines += ''
        $lines += ('Security score: ' + $s.Score + ' / 100  (' + $s.Rating + ')')
        $lines += ''
    }

    if ($Actions -and $Actions.Count -gt 0) {
        $lines += '===== Applying hardening ====='
        foreach ($a in $Actions) { $lines += ('  ' + $a) }
        $lines += ''
    }

    $lines | Out-File -FilePath $path -Encoding UTF8
    return $path
}

# =======================================================================
#  Main (done for you)
# =======================================================================

Write-Host ($ToolName + ' Windows Hardening Toolkit') -ForegroundColor Cyan
Show-Popup ($ToolName + ' is starting a security ' + $Mode + '.') ($ToolName + ' starting')

$elevated = Test-Admin
if (-not $elevated) {
    Write-Host 'Note: you are NOT running as Administrator.' -ForegroundColor Yellow
    Write-Host 'Audit will run, but some checks and all fixes need Administrator.' -ForegroundColor Yellow
}

if ($Mode -eq 'Apply') {
    if (-not $elevated) {
        Write-Host 'Apply mode needs Administrator. Re-open PowerShell as administrator and run again with -Mode Apply.' -ForegroundColor Red
        Show-Popup 'Apply mode needs Administrator. Re-run in an elevated PowerShell.' ($ToolName + ' stopped')
        return
    }

    $before = Invoke-Audit -Label 'BEFORE'

    Write-Host '=== Applying safe hardening fixes ===' -ForegroundColor Cyan
    $actions = Invoke-Apply
    foreach ($a in $actions) { Write-Host ('  ' + $a) -ForegroundColor Green }

    $after = Invoke-Audit -Label 'AFTER'

    $report = Write-Report -Summaries @($before, $after) -Actions $actions
    Write-Host ('Report written: ' + $report) -ForegroundColor Cyan

    Show-Popup ($ToolName + ' apply complete.  Before ' + $before.Score + ' / 100,  After ' + $after.Score + ' / 100  (' + $after.Rating + ')') ($ToolName + ' complete')
}
else {
    $audit = Invoke-Audit

    $report = Write-Report -Summaries @($audit) -Actions @()
    Write-Host ('Report written: ' + $report) -ForegroundColor Cyan

    Show-Popup ($ToolName + ' audit complete.  Score ' + $audit.Score + ' / 100  (' + $audit.Rating + ')') ($ToolName + ' complete')
}
