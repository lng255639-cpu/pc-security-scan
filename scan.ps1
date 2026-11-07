<#
  pc-security-scan / scan.ps1
  Read-only Windows security posture scan. Changes nothing on the system.
  Output: one JSON file. Works without admin; some checks need admin and
  report "needs_admin" instead of failing.

  Usage:
    powershell -NoProfile -ExecutionPolicy Bypass -File scan.ps1 -Out C:\path\scan.json [-Quick]

  -Quick skips Authenticode signature checks (the slowest part).
#>
param(
    [Parameter(Mandatory = $true)][string]$Out,
    [switch]$Quick
)

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

$scanStart = (Get-Date).AddSeconds(-5)
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$R = [ordered]@{}
$R.meta = [ordered]@{
    scanned_at   = (Get-Date).ToString('s')
    computer     = $env:COMPUTERNAME
    user         = $env:USERNAME
    is_admin     = $isAdmin
    quick        = [bool]$Quick
    ps_version   = $PSVersionTable.PSVersion.ToString()
}

$timings = [ordered]@{}
$R.meta.timings_sec = $timings
function Try-Run([string]$name, [scriptblock]$sb) {
    $t0 = [Diagnostics.Stopwatch]::StartNew()
    [Console]::Error.WriteLine("[scan] $name ...")
    try { $v = & $sb }
    catch { $v = [ordered]@{ error = $_.Exception.Message } }
    $timings[$name] = [Math]::Round($t0.Elapsed.TotalSeconds, 1)
    [Console]::Error.WriteLine("[scan] $name done $($timings[$name])s")
    return $v
}

# user-writable / suspicious locations for executables
$suspectDirs = @(
    $env:TEMP, $env:TMP, "$env:USERPROFILE\Downloads", "$env:PUBLIC",
    "$env:APPDATA", "$env:LOCALAPPDATA\Temp", 'C:\ProgramData', 'C:\Users\Public',
    "$env:WINDIR\Temp"
) | Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\').ToLower() }

function Test-SuspectPath([string]$p) {
    if (-not $p) { return $false }
    $l = $p.ToLower()
    foreach ($d in $suspectDirs) { if ($l.StartsWith($d)) { return $true } }
    return $false
}

$sigCache = @{}
function Get-Sig([string]$path) {
    if ($Quick -or -not $path -or -not (Test-Path -LiteralPath $path)) { return $null }
    if ($sigCache.ContainsKey($path)) { return $sigCache[$path] }
    try {
        $s = Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop
        $o = [ordered]@{ status = "$($s.Status)"; signer = $(if ($s.SignerCertificate) { ($s.SignerCertificate.Subject -replace '^CN=("[^"]+"|[^,]+).*', '$1').Trim('"') } else { $null }) }
    } catch { $o = [ordered]@{ status = 'unreadable'; signer = $null } }
    $sigCache[$path] = $o
    return $o
}

# extract exe path from a command line
function Get-ExePath([string]$cmd) {
    if (-not $cmd) { return $null }
    $c = [Environment]::ExpandEnvironmentVariables($cmd.Trim())
    if ($c.StartsWith('"')) { $e = $c.IndexOf('"', 1); if ($e -gt 1) { return $c.Substring(1, $e - 1) } }
    $m = [regex]::Match($c, '^(.+?\.(exe|com|bat|cmd|ps1|vbs|js|dll|scr))(\s|$|,)', 'IgnoreCase')
    if ($m.Success) { return $m.Groups[1].Value }
    return ($c -split '\s')[0]
}

$lolbins = '(^|[\\/"\s])(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|msiexec)(\.exe)?([\s"]|$)'
$encPattern = '\s-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}|FromBase64String|DownloadString|DownloadFile|Invoke-WebRequest|\biwr\s|\bIEX\b|Invoke-Expression|Start-BitsTransfer|curl(\.exe)?\s+.*http'

function Score-Cmd([string]$cmd, [string]$exe) {
    $flags = @()
    $isLol = $cmd -match $lolbins
    if ($isLol) { $flags += 'lolbin' }
    if ($cmd -match $encPattern) { $flags += 'download_or_encoded' }
    elseif ($isLol -and $cmd -match 'https?://') { $flags += 'lolbin_with_url' }
    if ((Test-SuspectPath $exe) -and $exe -notmatch '^C:\\ProgramData\\Microsoft\\Windows Defender\\') { $flags += 'user_writable_path' }
    if ($exe -and -not (Test-Path -LiteralPath $exe) -and $exe -match '\\') { $flags += 'missing_file' }
    return $flags
}

# ---------------- 1. OS & patching ----------------
$R.os = Try-Run os {
    $os = Get-CimInstance Win32_OperatingSystem
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $hf = Get-HotFix | Where-Object InstalledOn | Sort-Object InstalledOn -Descending
    $pending = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
               (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
    [ordered]@{
        caption           = $os.Caption
        version           = $os.Version
        display_version   = $cv.DisplayVersion
        build             = "$($cv.CurrentBuild).$($cv.UBR)"
        last_boot         = $os.LastBootUpTime.ToString('s')
        latest_hotfix     = $(if ($hf) { $hf[0].HotFixID })
        latest_hotfix_on  = $(if ($hf) { $hf[0].InstalledOn.ToString('yyyy-MM-dd') })
        days_since_patch  = $(if ($hf) { [int]((Get-Date) - $hf[0].InstalledOn).TotalDays })
        reboot_pending    = $pending
        wu_paused_until   = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings').PauseUpdatesExpiryTime
    }
}

# ---------------- 2. Antivirus / Defender ----------------
$R.antivirus = Try-Run av {
    $av = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct |
        ForEach-Object {
            $st = '{0:X6}' -f $_.productState
            [ordered]@{ name = $_.displayName; enabled = ($st.Substring(2, 2) -in '10', '11'); up_to_date = ($st.Substring(4, 2) -eq '00'); exe = $_.pathToSignedProductExe }
        }
    $mp = Get-MpComputerStatus
    $pref = Get-MpPreference
    $excl = @($pref.ExclusionPath) + @($pref.ExclusionProcess) + @($pref.ExclusionExtension) | Where-Object { $_ }
    [ordered]@{
        products = @($av)
        defender = $(if ($mp) { [ordered]@{
            am_service_enabled   = $mp.AMServiceEnabled
            realtime             = $mp.RealTimeProtectionEnabled
            behavior_monitor     = $mp.BehaviorMonitorEnabled
            ioav                 = $mp.IoavProtectionEnabled
            tamper_protection    = $mp.IsTamperProtected
            signature_age_days   = $mp.AntivirusSignatureAge
            quick_scan_age_days  = $mp.QuickScanAge
            full_scan_age_days   = $mp.FullScanAge
            pua_protection       = $pref.PUAProtection
            cloud_protection     = $pref.MAPSReporting
            controlled_folder    = $pref.EnableControlledFolderAccess
        } })
        exclusions = $(if ($excl -match 'Must be an administrator') { 'needs_admin' } else { @($excl) })
        recent_threats = @(Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending | Select-Object -First 15 | ForEach-Object {
            $t = Get-MpThreat -ThreatID $_.ThreatID
            [ordered]@{ name = $t.ThreatName; detected = $_.InitialDetectionTime.ToString('s'); resources = @($_.Resources | Select-Object -First 3); action_success = $_.ActionSuccess }
        })
    }
}

# ---------------- 3. Firewall ----------------
$R.firewall = Try-Run fw {
    @(Get-NetFirewallProfile | ForEach-Object { [ordered]@{ profile = $_.Name; enabled = "$($_.Enabled)"; default_inbound = "$($_.DefaultInboundAction)" } })
}
$R.network_profile = Try-Run np {
    @(Get-NetConnectionProfile | ForEach-Object { [ordered]@{ name = $_.Name; category = "$($_.NetworkCategory)"; interface = $_.InterfaceAlias } })
}

# ---------------- 4. Hardening settings ----------------
$R.hardening = Try-Run hard {
    $pol = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $ts = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $rdpTcp = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
    $smb1 = try { (Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol } catch { 'needs_admin' }
    $sb = try { Confirm-SecureBootUEFI -ErrorAction Stop } catch {
        $v = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State').UEFISecureBootEnabled
        if ($null -ne $v) { [bool]$v } else { 'unknown' } }
    $tpm = try { Get-CimInstance -Namespace root/cimv2/Security/MicrosoftTpm -ClassName Win32_Tpm -ErrorAction Stop } catch { $null }
    $vbs = try { Get-CimInstance -Namespace root/Microsoft/Windows/DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop } catch { $null }
    $bl = try { Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop } catch { $null }
    $blText = $null
    if (-not $bl) { $blText = try { (manage-bde -status $env:SystemDrive 2>$null) -join "`n" } catch { $null } }
    if ($blText -match 'Access is denied|denied|administrative|存取被拒|拒絕存取|嘗試被拒|系統管理') { $blText = $null }
    $autorun = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer').NoDriveTypeAutoRun
    $remReg = Get-Service RemoteRegistry
    $winrm = Get-Service WinRM
    $ssh = Get-Service sshd
    [ordered]@{
        uac_enabled               = $pol.EnableLUA
        uac_consent_prompt_admin  = $pol.ConsentPromptBehaviorAdmin   # 0 = no prompt (bad), 5 = default
        uac_secure_desktop        = $pol.PromptOnSecureDesktop
        rdp_enabled               = ($ts.fDenyTSConnections -eq 0)
        rdp_nla                   = $rdpTcp.UserAuthentication
        smb1_server               = $smb1
        lsa_protection_runasppl   = $lsa.RunAsPPL
        secure_boot               = $sb
        tpm_present               = $(if ($tpm) { $true } elseif ($isAdmin) { $false } else { 'needs_admin' })
        tpm_enabled               = $(if ($tpm) { $tpm.IsEnabled_InitialValue })
        vbs_status                = $(if ($vbs) { $vbs.VirtualizationBasedSecurityStatus })  # 2 = running
        credential_guard_running  = $(if ($vbs) { 1 -in $vbs.SecurityServicesRunning })
        hvci_running              = $(if ($vbs) { 2 -in $vbs.SecurityServicesRunning })
        bitlocker_system_drive    = $(if ($bl) { [ordered]@{ protection = "$($bl.ProtectionStatus)"; encryption = "$($bl.VolumeStatus)"; method = "$($bl.EncryptionMethod)" } } elseif ($blText -match 'Protection On|保護開啟') { 'on' } elseif ($blText) { $blText.Substring(0, [Math]::Min(400, $blText.Length)) } else { 'needs_admin_or_unavailable' })
        autorun_policy            = $autorun
        remote_registry           = $(if ($remReg) { "$($remReg.Status)/$($remReg.StartType)" })
        winrm                     = $(if ($winrm) { "$($winrm.Status)/$($winrm.StartType)" })
        openssh_server            = $(if ($ssh) { "$($ssh.Status)/$($ssh.StartType)" } else { 'not_installed' })
        ps_execution_policy       = @(Get-ExecutionPolicy -List | ForEach-Object { "$($_.Scope)=$($_.ExecutionPolicy)" })
        ps_v2_engine              = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine').PowerShellVersion
        smartscreen               = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer').SmartScreenEnabled
        developer_mode            = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock').AllowDevelopmentWithoutDevLicense
    }
}

# ---------------- 5. Accounts ----------------
$R.accounts = Try-Run acc {
    $admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object { "$($_.Name) [$($_.PrincipalSource)]" })
    $users = @(Get-LocalUser | ForEach-Object {
        [ordered]@{ name = $_.Name; enabled = $_.Enabled; password_required = $_.PasswordRequired; password_last_set = $(if ($_.PasswordLastSet) { $_.PasswordLastSet.ToString('yyyy-MM-dd') }); last_logon = $(if ($_.LastLogon) { $_.LastLogon.ToString('yyyy-MM-dd') }); sid_tail = ($_.SID.Value -split '-')[-1] }
    })
    $auto = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    [ordered]@{
        administrators     = $admins
        local_users        = $users
        current_user_admin = $isAdmin
        autologon_enabled  = ($auto.AutoAdminLogon -eq '1')
        autologon_has_plaintext_password = [bool]$auto.DefaultPassword   # value itself never read out
    }
}

# ---------------- 6. Persistence: Run keys, startup folders ----------------
$R.autoruns = Try-Run runs {
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
    )
    $items = @()
    foreach ($k in $keys) {
        $p = Get-ItemProperty $k
        if (-not $p) { continue }
        $p.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
            $exe = Get-ExePath "$($_.Value)"
            $items += [ordered]@{ where = $k; name = $_.Name; command = "$($_.Value)"; exe = $exe; signature = (Get-Sig $exe); flags = @(Score-Cmd "$($_.Value)" $exe) }
        }
    }
    $folders = @("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup", "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp")
    $sh = New-Object -ComObject WScript.Shell
    foreach ($f in $folders) {
        Get-ChildItem -LiteralPath $f -File | Where-Object Name -ne 'desktop.ini' | ForEach-Object {
            $target = $_.FullName; $args_ = ''
            if ($_.Extension -eq '.lnk') { $l = $sh.CreateShortcut($_.FullName); $target = $l.TargetPath; $args_ = $l.Arguments }
            $items += [ordered]@{ where = $f; name = $_.Name; command = "$target $args_".Trim(); exe = $target; signature = (Get-Sig $target); flags = @(Score-Cmd "$target $args_" $target) }
        }
    }
    # Winlogon / IFEO hijack points
    $wl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $extra = [ordered]@{
        winlogon_shell    = $wl.Shell
        winlogon_userinit = $wl.Userinit
        ifeo_debuggers    = @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' | ForEach-Object {
            $d = (Get-ItemProperty $_.PSPath).Debugger; if ($d) { "$($_.PSChildName) => $d" } })
        appinit_dlls      = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows').AppInit_DLLs
    }
    [ordered]@{ entries = $items; hijack_points = $extra }
}

# ---------------- 7. Scheduled tasks (non-Microsoft) ----------------
$R.scheduled_tasks = Try-Run tasks {
    @(Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' -and $_.State -ne 'Disabled' } | ForEach-Object {
        $a = $_.Actions | Where-Object { $_.Execute } | Select-Object -First 1
        $cmd = "$($a.Execute) $($a.Arguments)".Trim()
        $exe = Get-ExePath "$($a.Execute)"
        [ordered]@{ name = "$($_.TaskPath)$($_.TaskName)"; author = $_.Author; run_as = $_.Principal.UserId; run_level = "$($_.Principal.RunLevel)"; command = $cmd; signature = (Get-Sig $exe); flags = @(Score-Cmd $cmd $exe); triggers = @($_.Triggers | ForEach-Object { $_.CimClass.CimClassName -replace 'MSFT_Task|Trigger', '' }) }
    })
}

# ---------------- 8. Services (non-system paths) ----------------
$R.services = Try-Run svc {
    @(Get-CimInstance Win32_Service | ForEach-Object {
        $exe = Get-ExePath $_.PathName
        $unquoted = ($_.PathName -and -not $_.PathName.StartsWith('"') -and ($exe -match ' ') -and $exe -notmatch '^C:\\Windows\\')
        $flags = @(Score-Cmd $_.PathName $exe)
        if ($unquoted) { $flags += 'unquoted_path_with_space' }
        $isWin = $exe -match '^C:\\Windows\\'
        if (-not $isWin -or $flags.Count) {
            [ordered]@{ name = $_.Name; display = $_.DisplayName; state = $_.State; start = $_.StartMode; account = $_.StartName; path = $_.PathName; signature = $(if (-not $isWin) { Get-Sig $exe }); flags = $flags }
        }
    })
}

# ---------------- 9. WMI persistence (needs admin) ----------------
$R.wmi_persistence = Try-Run wmi {
    if (-not $isAdmin) { 'needs_admin' } else {
        [ordered]@{
            filters   = @(Get-CimInstance -Namespace root/subscription -ClassName __EventFilter | ForEach-Object { "$($_.Name): $($_.Query)" })
            consumers = @(Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer | ForEach-Object { "$($_.Name): $($_.CommandLineTemplate)" }) +
                        @(Get-CimInstance -Namespace root/subscription -ClassName ActiveScriptEventConsumer | ForEach-Object { "$($_.Name): script" })
        }
    }
}

# ---------------- 10. Processes ----------------
$R.processes = Try-Run proc {
    $all = Get-CimInstance Win32_Process
    @($all | Where-Object { $_.ExecutablePath -and $_.ExecutablePath -notmatch '^C:\\Windows\\' } |
        Group-Object ExecutablePath | ForEach-Object {
            $p = $_.Group[0]
            $flags = @(Score-Cmd "$($p.CommandLine)" $p.ExecutablePath)
            $sig = Get-Sig $p.ExecutablePath
            if ($sig -and $sig.status -ne 'Valid') { $flags += 'not_validly_signed' }
            [ordered]@{ name = $p.Name; count = $_.Count; path = $p.ExecutablePath; signature = $sig; flags = $flags; cmd_sample = $(if ($flags.Count) { "$($p.CommandLine)".Substring(0, [Math]::Min(300, "$($p.CommandLine)".Length)) }) }
        } | Where-Object { $_.flags.Count -gt 0 -or $Quick })
}
$R.process_count = (Get-Process).Count

# ---------------- 11. Network exposure ----------------
$procNames = @{}; Get-Process | ForEach-Object { $procNames[[int]$_.Id] = $_.ProcessName }
$R.listening = Try-Run listen {
    @(Get-NetTCPConnection -State Listen | Where-Object { $_.LocalAddress -notin '127.0.0.1', '::1' } |
        Sort-Object LocalPort -Unique | ForEach-Object {
            [ordered]@{ port = $_.LocalPort; address = $_.LocalAddress; process = $procNames[[int]$_.OwningProcess]; pid = $_.OwningProcess }
        })
}
$R.listening_udp = Try-Run udp {
    @(Get-NetUDPEndpoint | Where-Object { $_.LocalAddress -notin '127.0.0.1', '::1' -and $_.LocalPort -lt 49152 } |
        Sort-Object LocalPort -Unique | ForEach-Object { [ordered]@{ port = $_.LocalPort; process = $procNames[[int]$_.OwningProcess] } })
}
$R.outbound = Try-Run outb {
    @(Get-NetTCPConnection -State Established | Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1|0\.0\.0\.0|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|fe80|::$)' } |
        Group-Object { "$($procNames[[int]$_.OwningProcess])|$($_.RemoteAddress)|$($_.RemotePort)" } |
        ForEach-Object { $s = $_.Name -split '\|'; [ordered]@{ process = $s[0]; remote = $s[1]; port = [int]$s[2]; conns = $_.Count } } |
        Sort-Object process)
}
$R.shares = Try-Run shares {
    @(Get-SmbShare | Where-Object { $_.Name -notmatch '^\w\$$|^ADMIN\$$|^IPC\$$|^print\$$' } | ForEach-Object {
        [ordered]@{ name = $_.Name; path = $_.Path; access = @(Get-SmbShareAccess -Name $_.Name | ForEach-Object { "$($_.AccountName):$($_.AccessRight)" }) }
    })
}

# ---------------- 12. DNS / proxy / hosts ----------------
$R.network_config = Try-Run netcfg {
    $ie = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    $hostsRaw = @([IO.File]::ReadAllLines("$env:WINDIR\System32\drivers\etc\hosts") | Where-Object { $_ -match '^\s*[^#\s]' } | ForEach-Object { ($_ -replace '#.*$', '').Trim() } | Where-Object { $_ } | Select-Object -Unique)
    $hBlock = @(); $hRedirect = @()
    foreach ($h in $hostsRaw) {
        $parts = $h -split '\s+'
        if ($parts[0] -match '^(0\.0\.0\.0|127\.0\.0\.1|::1?|::0)$') { $hBlock += $parts[1..($parts.Count - 1)] } else { $hRedirect += $h }
    }
    $hosts = [ordered]@{
        total_lines      = $hostsRaw.Count
        redirects        = @($hRedirect | Select-Object -First 50)   # name -> other IP: review every one
        blocked_count    = $hBlock.Count
        blocked_by_domain = @($hBlock | Group-Object { ($_ -split '\.')[-2..-1] -join '.' } | Sort-Object Count -Descending | Select-Object -First 15 | ForEach-Object { "$($_.Name) x$($_.Count)" })
    }
    $wh = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections').WinHttpSettings
    $winhttp = 'direct'
    if ($wh -and $wh.Length -ge 16) {
        $len = [BitConverter]::ToInt32($wh, 12)
        if ($len -gt 0 -and $wh.Length -ge 16 + $len) { $winhttp = [Text.Encoding]::ASCII.GetString($wh, 16, $len) }
    }
    [ordered]@{
        dns_servers      = @(Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object ServerAddresses | ForEach-Object { "$($_.InterfaceAlias): $($_.ServerAddresses -join ', ')" })
        proxy_enabled    = $ie.ProxyEnable
        proxy_server     = $ie.ProxyServer
        proxy_pac        = $ie.AutoConfigURL
        winhttp_proxy    = $winhttp
        hosts            = $hosts
        root_certs_nonms = @(Get-ChildItem Cert:\CurrentUser\Root, Cert:\LocalMachine\Root |
            Where-Object { $_.Subject -notmatch 'Microsoft|DigiCert|GlobalSign|Sectigo|Comodo|USERTrust|Entrust|GoDaddy|Starfield|ISRG|Baltimore|VeriSign|thawte|QuoVadis|IdenTrust|Amazon|Certum|SSL\.com|Go Daddy|AAA Certificate|Symantec|GeoTrust|Buypass|SECOM|Actalis|Chunghwa|TWCA|HiPKI|Hongkong Post|Copyright \(c\) 1997|NO LIABILITY|Class 3 Public' } |
            Sort-Object Thumbprint -Unique | ForEach-Object { [ordered]@{ subject = $_.Subject; store = $_.PSParentPath -replace '.*::', ''; not_after = $_.NotAfter.ToString('yyyy-MM-dd') } })
        wifi_open_profiles = @(netsh wlan show profiles 2>$null | Select-String 'All User Profile|所有使用者設定檔' | ForEach-Object {
            $n = ($_ -split ':', 2)[1].Trim()
            $info = (netsh wlan show profile name="$n" 2>$null) -join "`n"   # no key=clear: passwords never read
            if ($info -match '(Authentication|驗證)\s*:\s*Open') { $n } })
    }
}

# ---------------- 13. Installed software ----------------
$R.software = Try-Run sw {
    $paths = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    @(Get-ItemProperty $paths | Where-Object { $_.DisplayName -and -not $_.SystemComponent -and $_.DisplayName -notmatch '^(KB\d+|Security Update|Update for)' } |
        Sort-Object DisplayName -Unique | ForEach-Object {
            [ordered]@{ name = $_.DisplayName; version = $_.DisplayVersion; publisher = $_.Publisher; installed = $_.InstallDate; location = $_.InstallLocation }
        })
}
$R.recent_installs_30d = @($R.software | Where-Object { $_.installed -match '^\d{8}$' -and [datetime]::ParseExact($_.installed, 'yyyyMMdd', $null) -gt (Get-Date).AddDays(-30) } | ForEach-Object { "$($_.name) $($_.version) ($($_.installed))" })

# ---------------- 14. Browser extensions ----------------
$R.browser_extensions = Try-Run ext {
    $out = @()
    $roots = [ordered]@{
        Chrome = "$env:LOCALAPPDATA\Google\Chrome\User Data"
        Edge   = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
        Brave  = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"
    }
    foreach ($b in $roots.Keys) {
        if (-not (Test-Path $roots[$b])) { continue }
        Get-ChildItem $roots[$b] -Directory | Where-Object { $_.Name -match '^(Default|Profile \d+)$' } | ForEach-Object {
            $prof = $_.Name
            Get-ChildItem "$($_.FullName)\Extensions" -Directory | ForEach-Object {
                $id = $_.Name
                $mf = Get-ChildItem $_.FullName -Recurse -Filter manifest.json -Depth 1 | Select-Object -First 1
                if (-not $mf) { return }
                $j = Get-Content $mf.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
                $name = $j.name
                if ($name -match '^__MSG_(.+)__$') {
                    $key = $Matches[1]
                    $loc = Get-ChildItem "$($mf.DirectoryName)\_locales" -Recurse -Filter messages.json | Where-Object { $_.Directory.Name -in 'en', 'en_US', 'zh_TW' } | Select-Object -First 1
                    if ($loc) { $m = Get-Content $loc.FullName -Raw -Encoding UTF8 | ConvertFrom-Json; $prop = $m.PSObject.Properties | Where-Object { $_.Name -ieq $key } | Select-Object -First 1; if ($prop) { $name = $prop.Value.message } }
                }
                $perms = @($j.permissions) + @($j.host_permissions) + @($j.optional_permissions) | Where-Object { $_ -is [string] }
                $risky = @($perms | Where-Object { $_ -match '<all_urls>|^\*://\*/\*|^https?://\*/\*|webRequest|debugger|nativeMessaging|cookies|clipboardRead|history|management|proxy|scripting' })
                if ($j.content_scripts | Where-Object { $_.matches -match '<all_urls>|\*://\*/\*' }) { $risky += 'content_scripts_on_all_sites' }
                $out += [ordered]@{ browser = $b; profile = $prof; id = $id; name = $name; version = $j.version; risky_permissions = @($risky | Select-Object -Unique); from_store = [bool]$j.update_url -and $j.update_url -match 'google\.com|microsoft\.com' }
            }
        }
    }
    $ff = "$env:APPDATA\Mozilla\Firefox\Profiles"
    if (Test-Path $ff) {
        Get-ChildItem $ff -Recurse -Filter extensions.json -Depth 1 | ForEach-Object {
            (Get-Content $_.FullName -Raw -Encoding UTF8 | ConvertFrom-Json).addons | Where-Object { $_.type -eq 'extension' -and $_.location -notmatch '^app-' -and -not $_.isSystem -and -not $_.isBuiltin } | ForEach-Object {
                $out += [ordered]@{ browser = 'Firefox'; profile = ''; id = $_.id; name = $_.defaultLocale.name; version = $_.version; risky_permissions = @($_.userPermissions.permissions + $_.userPermissions.origins | Where-Object { $_ -match '<all_urls>|webRequest|cookies|nativeMessaging|proxy' }); from_store = ($_.sourceURI -match 'mozilla') }
            }
        }
    }
    $out
}

# ---------------- 15. Recent executables in download / temp ----------------
$R.recent_executables = Try-Run recent {
    $dirs = "$env:USERPROFILE\Downloads", $env:TEMP, "$env:USERPROFILE\Desktop", "$env:PUBLIC", "$env:APPDATA"
    @(foreach ($d in $dirs) {
        # -Include is silently ignored with -LiteralPath, so filter by extension here
        Get-ChildItem -LiteralPath $d -File -Recurse -Depth 2 |
            Where-Object { $_.Extension -match '^\.(exe|scr|msi|bat|cmd|ps1|vbs|vbe|js|jse|wsf|hta|lnk|iso|img|vhd|vhdx|cpl|pif)$' -and $_.LastWriteTime -gt (Get-Date).AddDays(-14) -and $_.Length -gt 0 } |
            Where-Object { -not ($_.Extension -eq '.js' -and $_.FullName -match '\\AppData\\Local\\Temp\\[0-9a-f-]{36}\.tmp\.js$') } |
            Select-Object -First 40 | ForEach-Object {
                $zone = "$(Get-Content -LiteralPath $_.FullName -Stream Zone.Identifier -Raw)" -replace "`r?`n", ' '
                $isPE = $false
                try { $fs = [IO.File]::OpenRead($_.FullName); $b = New-Object byte[] 2; [void]$fs.Read($b, 0, 2); $fs.Close(); $isPE = ($b[0] -eq 0x4D -and $b[1] -eq 0x5A) } catch {}
                $lnkTarget = $null
                if ($_.Extension -eq '.lnk') { try { $l = (New-Object -ComObject WScript.Shell).CreateShortcut($_.FullName); $lnkTarget = "$($l.TargetPath) $($l.Arguments)".Trim() } catch {} }
                [ordered]@{ path = $_.FullName; size_kb = [int]($_.Length / 1KB); modified = $_.LastWriteTime.ToString('s'); is_pe_binary = $isPE; signature = $(if ($isPE -or $_.Extension -in '.msi', '.ps1') { Get-Sig $_.FullName }); from_internet = ($zone -match 'ZoneId=3'); host_url = $(if ($zone -match 'HostUrl=(\S+)') { $Matches[1] }); double_ext = ($_.Name -match '\.(pdf|docx?|xlsx?|jpg|png|txt|mp4)\.(exe|scr|lnk|js|vbs|hta|cmd|bat)$'); lnk_target = $lnkTarget; lnk_flags = $(if ($lnkTarget) { @(Score-Cmd $lnkTarget (Get-ExePath $lnkTarget)) }) }
            }
    })
}

# ---------------- 16. Developer / AI-agent supply chain ----------------
$R.dev_supply_chain = Try-Run dev {
    $home_ = $env:USERPROFILE
    $secretFiles = @('.aws\credentials', '.azure\accessTokens.json', '.config\gcloud\credentials.db', '.docker\config.json', '.npmrc', '.pypirc', '.git-credentials', '.netrc', '.kube\config') |
        ForEach-Object { $p = Join-Path $home_ $_; if (Test-Path $p) { $p } }
    $npmrcToken = $false
    if (Test-Path "$home_\.npmrc") { $npmrcToken = [bool](Select-String -Path "$home_\.npmrc" -Pattern '_authToken|_auth\s*=' -Quiet) }
    $sshKeys = @(Get-ChildItem "$home_\.ssh" -File | Where-Object { $_.Name -notmatch '\.pub$|known_hosts|config|authorized_keys' } | ForEach-Object {
        $head = Get-Content $_.FullName -TotalCount 5 -Raw
        $enc = ($head -match 'ENCRYPTED') -or ($head -match 'OPENSSH PRIVATE KEY' -and ([Convert]::FromBase64String(((Get-Content $_.FullName | Where-Object { $_ -notmatch '-----' }) -join ''))[0..60] -join ',') -notmatch '110,111,110,101')
        [ordered]@{ file = $_.Name; looks_encrypted = $enc }
    })
    $npmGlobal = $null
    if (Get-Command npm -ErrorAction SilentlyContinue) { $npmGlobal = @((npm ls -g --depth=0 2>$null) | Select-Object -Skip 1 | ForEach-Object { ($_ -replace '^[\s+`|\\-]+', '').Trim() } | Where-Object { $_ }) }
    $pipUser = $null
    $claude = [ordered]@{}
    $cs = "$home_\.claude\settings.json"
    if (Test-Path $cs) {
        $j = Get-Content $cs -Raw -Encoding UTF8 | ConvertFrom-Json
        $claude.hooks = @($j.hooks.PSObject.Properties | ForEach-Object { $ev = $_.Name; $_.Value | ForEach-Object { $_.hooks | ForEach-Object { "$ev => $($_.command)" } } })
        $claude.allow_rules = @($j.permissions.allow | Where-Object { $_ })
        $claude.bypass_or_skip = [bool]($j.permissions.defaultMode -match 'bypass') -or [bool]$j.skipDangerousModePermissionPrompt
        $claude.enabled_plugins = @($j.enabledPlugins.PSObject.Properties | Where-Object Value | ForEach-Object Name)
        $claude.marketplaces = @($j.extraKnownMarketplaces.PSObject.Properties | ForEach-Object { "$($_.Name): $($_.Value.source.repo)$($_.Value.source.url)" })
    }
    $cj = "$home_\.claude.json"
    if (Test-Path $cj) {
        $j2 = Get-Content $cj -Raw -Encoding UTF8 | ConvertFrom-Json
        $claude.mcp_servers_global = @($j2.mcpServers.PSObject.Properties | ForEach-Object { "$($_.Name): $($_.Value.command) $($_.Value.args -join ' ')$($_.Value.url)" })
    }
    $claude.user_skills = @(Get-ChildItem "$home_\.claude\skills" -Directory | ForEach-Object Name)
    $desk = "$env:APPDATA\Claude\claude_desktop_config.json"
    if (Test-Path $desk) { $claude.desktop_mcp = @((Get-Content $desk -Raw -Encoding UTF8 | ConvertFrom-Json).mcpServers.PSObject.Properties | Where-Object { $_.Name } | ForEach-Object { "$($_.Name): $($_.Value.command) $($_.Value.args -join ' ')" }) }
    $vsc = @(Get-ChildItem "$home_\.vscode\extensions", "$home_\.cursor\extensions" -Directory | ForEach-Object { $_.Name })
    [ordered]@{
        credential_files_present = @($secretFiles)   # only existence; contents never read
        npmrc_has_token          = $npmrcToken
        ssh_private_keys         = $sshKeys
        npm_global_packages      = $npmGlobal
        vscode_cursor_extensions = $vsc
        claude                   = $claude
        path_user_writable_dirs  = @(($env:PATH -split ';') | Where-Object { $_ -and (Test-SuspectPath $_) })
    }
}

# ---------------- 17. Security event log hints ----------------
$R.event_hints = Try-Run ev {
    $since = (Get-Date).AddDays(-7)
    [ordered]@{
        failed_logons_7d     = $(if ($isAdmin) { @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = $since } -MaxEvents 500).Count } else { 'needs_admin' })
        new_services_7d      = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 7045; StartTime = $since } -MaxEvents 50 | ForEach-Object { "$($_.TimeCreated.ToString('s')) $($_.Properties[0].Value) => $($_.Properties[1].Value)" })
        defender_detections_7d = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = 1116, 1117, 5001; StartTime = $since } -MaxEvents 30 | ForEach-Object { "$($_.TimeCreated.ToString('s')) id=$($_.Id) $((($_.Message -split "`n") | Where-Object { $_ -match '\S' } | Select-Object -First 3) -join ' | ')" })
        # 5007 (config changed) fires many times a day for routine updates; keep only
        # changes that touch exclusions or switch protection off
        defender_config_changes_7d = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = 5007; StartTime = $since } -MaxEvents 300 |
            ForEach-Object { $t = $_.TimeCreated.ToString('s'); ($_.Message -split "`n") | Where-Object { $_ -match 'Exclusions|DisableRealtimeMonitoring|DisableBehaviorMonitoring|DisableIOAV|DisableAntiSpyware|TamperProtection|SpynetReporting' } | ForEach-Object { "$t $($_.Trim())" } } |
            Select-Object -Unique -First 30)
        defender_5007_count_7d = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = 5007; StartTime = $since } -MaxEvents 1000).Count
        # PowerShell auto-flags "suspicious" script blocks (Level 3). Skip this scan's own
        # blocks and built-in CIM cmdletization module code.
        ps_scriptblock_warn_7d = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4104; Level = 3; StartTime = $since } -MaxEvents 200 |
            Where-Object { $_.TimeCreated -lt $scanStart -and $_.Properties[2].Value -notmatch '__cmdletization|Microsoft\.PowerShell\.Cmdletization' } |
            Select-Object -First 20 | ForEach-Object { $s = ($_.Properties[2].Value -replace '\s+', ' '); "$($_.TimeCreated.ToString('s')) [$($_.Properties[4].Value)] " + $s.Substring(0, [Math]::Min(200, $s.Length)) })
    }
}

# Flatten everything to plain primitives first: ConvertTo-Json in PS 5.1
# explodes (minutes, GBs) on rich .NET / CIM objects that slip into results.
function Norm($v, [int]$d = 0) {
    if ($null -eq $v) { return $null }
    # strings from Get-Content etc. carry hidden PSPath/PSDrive note properties
    # that ConvertTo-Json expands into huge objects -> rebuild a bare string
    if ($v -is [string]) { return [string]::Copy($v) }
    if ($v -is [psobject]) { $v = $v.PSObject.BaseObject }
    if ($v -is [string] -or $v -is [bool] -or $v -is [int] -or $v -is [long] -or $v -is [double] -or $v -is [decimal] -or
        $v -is [uint32] -or $v -is [uint16] -or $v -is [byte] -or $v -is [int16] -or $v -is [uint64] -or $v -is [single]) { return $v }
    if ($v -is [enum]) { return "$v" }
    if ($v -is [datetime]) { return $v.ToString('s') }
    if ($d -ge 10) { return "$v" }
    if ($v -is [Collections.IDictionary]) {
        $o = [ordered]@{}
        foreach ($k in @($v.Keys)) { $o["$k"] = Norm $v[$k] ($d + 1) }
        return $o
    }
    if ($v -is [Collections.IEnumerable]) { return , @(foreach ($x in $v) { Norm $x ($d + 1) }) }
    return "$v"
}
[Console]::Error.WriteLine("[scan] writing json ...")
$N = [ordered]@{}
foreach ($k in @($R.Keys)) {
    $t0 = [Diagnostics.Stopwatch]::StartNew()
    $N[$k] = Norm $R[$k]
    [Console]::Error.WriteLine("[json] $k norm $([Math]::Round($t0.Elapsed.TotalSeconds,1))s")
}
$json = $N | ConvertTo-Json -Depth 12
[IO.File]::WriteAllText($Out, $json, (New-Object Text.UTF8Encoding $false))
Write-Output "OK $Out  ($([int]((Get-Item $Out).Length / 1KB)) KB)"
