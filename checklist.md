# 判讀表

嚴重度：🔴 高（立即處理）、🟡 中（建議處理或需使用者確認）、🟢 正常。
計分：滿分 100，每個 🔴 扣 10、每個 🟡 扣 3，最低 0。90+ 良好、70–89 普通、<70 需處理。

## 0. 常見誤報（判讀前先排除）
- `default_inbound` = `NotConfigured`：等於系統預設「封鎖」，🟢。
- `full_scan_age_days` = 4294967295：代表「從沒跑過完整掃描」，不是錯誤值；列 🟡 建議跑一次。
- 本機帳號 `password_required` = false：綁 Microsoft 帳號或用 PIN 登入的帳號常見此旗標，不代表沒密碼；問使用者登入時有沒有密碼/PIN/Windows Hello，有就 🟢。
- `C:\Program Files\WindowsApps\...` 顯示 NotSigned：市集 App 用目錄簽章，Get-AuthenticodeSignature 讀不到，🟢。
- `C:\Program Files\Git\usr\bin\*.exe`、uv/pyenv 裝的 `python.exe`、自己打包的 exe（PyInstaller 等）未簽章：開發工具常態，🟢（使用者認得的前提下）。
- `ProgramData\Microsoft\Windows Defender\Platform\...`：Defender 本體，🟢。
- `.scr` 且 `is_pe_binary` = false：AutoCAD 腳本等文字檔，不是螢幕保護程式執行檔，🟢；`is_pe_binary` = true 的 `.scr` 才是 🔴。
- `cmd.exe /q /c del ... OneDrive...` 的 RunOnce：OneDrive 更新清理，🟢。
- `rundll32.exe url.dll,FileProtocolHandler <協定網址>` 的捷徑：Google Play Games 等啟動器常用，協定是已知 App 就 🟢。
- `crashpad_handler` 命令列帶網址：當機回報上傳位址，🟢。
- Defender 事件 5007 每天十幾次：例行更新；只看 `defender_config_changes_7d`（動到排除清單或關防護的才列出）。
- 「unquoted_path_with_space」但路徑在 `C:\Program Files` 底下：一般使用者無法寫 `C:\Program.exe`，實際風險低，🟡（可提醒廠商問題，不必急修）。
- hosts 大量 `0.0.0.0 *.adobe.io / adobestats.io`：封鎖 Adobe 授權驗證，**通常代表裝了破解版 Adobe**。本身不是惡意，但破解程式是常見木馬來源 → 🟡，建議確認來源並改正版或替代軟體。

## A. 系統修補（`os`）
| 條件 | 嚴重度 |
|---|---|
| `days_since_patch` > 60 | 🔴 |
| `days_since_patch` 31–60，或 `reboot_pending` = true，或 `wu_paused_until` 在未來 | 🟡 |
| Windows 版本已停止支援（Win10 22H2 於 2025-10-14 結束一般支援，除非有 ESU；Win11 各版本支援期限需查證） | 🔴 |

## B. 防毒（`antivirus`）
| 條件 | 嚴重度 |
|---|---|
| 沒有任何 `enabled` 的防毒，或 Defender `realtime` = false 且無第三方防毒 | 🔴 |
| `tamper_protection` = false | 🟡 |
| `signature_age_days` > 3 | 🟡（> 7 為 🔴） |
| `exclusions` 含 Temp、AppData、Downloads、整個磁碟、`.exe`、powershell 等 | 🔴 |
| `recent_threats` 有項目且 `action_success` = false | 🔴；成功處理的列 🟡 說明 |
| `pua_protection` = 0、`cloud_protection` = 0 | 🟡 |
| 同時開兩套即時防護的第三方防毒 | 🟡（衝突） |

## C. 防火牆與網路設定檔
| 條件 | 嚴重度 |
|---|---|
| 任一 profile `enabled` = False | 🔴（Public 關閉最嚴重） |
| `default_inbound` = Allow | 🔴 |
| 咖啡廳等公共網路被設成 Private | 🟡 |

## D. 強化設定（`hardening`）
| 條件 | 嚴重度 |
|---|---|
| `uac_enabled` = 0 或 `uac_consent_prompt_admin` = 0 | 🔴 |
| `rdp_enabled` = true 且 `rdp_nla` ≠ 1 | 🔴；有 NLA 但使用者沒在用 | 🟡 |
| `smb1_server` = true | 🔴 |
| BitLocker 系統碟未保護（筆電） | 🔴；桌機 🟡 |
| `secure_boot` = false | 🟡 |
| `lsa_protection_runasppl` 未設、`hvci_running` = false | 🟡（可選強化） |
| `remote_registry` / `winrm` / `openssh_server` 為 Running 且使用者不需要 | 🟡 |
| `ps_v2_engine` 存在（PowerShell 2.0 可繞過記錄） | 🟡 |
| `ps_execution_policy` 的 LocalMachine/CurrentUser = Unrestricted/Bypass | 🟡 |
| `smartscreen` = Off | 🟡 |

## E. 帳號（`accounts`）
| 條件 | 嚴重度 |
|---|---|
| Guest 或內建 Administrator（sid_tail 500/501）`enabled` = true | 🔴 |
| 啟用中帳號 `password_required` = false | 🔴 |
| `autologon_has_plaintext_password` = true | 🔴 |
| 日常使用帳號就是管理員 | 🟡（建議另建標準帳號日常用） |
| 不認得的管理員成員或本機帳號 | 🔴，請使用者確認 |

## F. 持久化 / 開機啟動（`autoruns`、`scheduled_tasks`、`services`、`wmi_persistence`）
| 條件 | 嚴重度 |
|---|---|
| `flags` 含 `download_or_encoded` | 🔴 |
| `user_writable_path` + 簽章非 Valid（或 NotSigned） | 🔴 |
| `lolbin`（powershell/mshta/rundll32 等）且參數指向使用者可寫路徑或網址 | 🔴 |
| `ifeo_debuggers` 有任何項目（非使用者自己設的除錯器） | 🔴 |
| `winlogon_shell` ≠ `explorer.exe`，或 `winlogon_userinit` 不是 `C:\Windows\system32\userinit.exe,` | 🔴 |
| `appinit_dlls` 非空 | 🔴 |
| WMI consumers 有非廠商項目（SCM Event Log Consumer 是正常的） | 🔴 |
| `missing_file`（指向不存在的檔） | 🟡（殘留，可清） |
| `unquoted_path_with_space` 的服務 | 🟡 |
| 近 7 天 `new_services_7d` 有使用者不認得的 | 🟡→問 |
| 知名廠商有效簽章放 AppData（Chrome、Teams、Discord、OneDrive、Spotify…） | 🟢 |

## G. 執行中程式（`processes`）
- 只列出 `flags` 非空的。未簽章且在 Temp/Downloads 執行 → 🔴；其餘 🟡 請使用者確認。

## H. 網路暴露（`listening`、`outbound`、`shares`、`network_config`）
| 條件 | 嚴重度 |
|---|---|
| 3389/445/5985/5986/22 在監聽且使用者不需要 | 🟡（防火牆關閉時 🔴） |
| 資料庫埠（3306/5432/27017/6379/9200）或開發伺服器綁 0.0.0.0 | 🟡 |
| 共用資料夾 access 含 `Everyone:Full` | 🔴；`Everyone:Read` 🟡 |
| `proxy_enabled` = 1 或 `proxy_pac` 有值，使用者不認得 | 🔴 |
| `hosts.redirects`（指到 0.0.0.0/127.0.0.1 以外 IP 的項目）含銀行、google、microsoft、windowsupdate、防毒廠商 | 🔴；開發用的內網對應 🟢 |
| `hosts.blocked_by_domain` 封鎖 windowsupdate、microsoft、防毒廠商網域 | 🔴（惡意程式阻止更新的手法） |
| `dns_servers` 為陌生公網 IP（非 ISP/路由器/1.1.1.1/8.8.8.8/9.9.9.9/168.95.1.1 等） | 🟡→查 |
| `root_certs_nonms` 有不認得的（Fiddler、公司 MITM、防毒 HTTPS 掃描屬常見來源，需說明） | 🔴→問 |
| `wifi_open_profiles` 有項目（會自動連開放 Wi-Fi） | 🟡 |
| `outbound` 有未簽章程式連外 | 🔴→查 |

## I. 軟體（`software`、`recent_installs_30d`）
- 已停止支援的軟體（例：Adobe Flash、舊版 Java 8 未更新、Python 2、IE 相關元件、舊版 WinRAR < 7.x） → 🔴。
- 版本落後且有已知被利用漏洞（查 CISA KEV 或廠商公告，用 WebSearch 查證） → 🔴；單純落後 → 🟡。
- 遠端控制軟體（AnyDesk、TeamViewer、RustDesk、ScreenConnect、UltraViewer）使用者沒在用 → 🔴（詐騙常用）。
- 近 30 天安裝、使用者不認得的 → 🟡→問。
- 盜版啟動工具（KMS、crack、activator 名稱） → 🔴。

## J. 瀏覽器擴充（`browser_extensions`）
- `from_store` = false 且有 `risky_permissions` → 🔴→問。
- 有 `<all_urls>`/cookies/webRequest 的商店擴充 → 🟡，提醒移除不用的。
- 名稱像「PDF 轉換」「免費 VPN」「影片下載」「優惠券」這類高風險類型 → 🟡。

## K. 下載與暫存（`recent_executables`）
- `from_internet` = true 且未簽章的 PE 檔（`is_pe_binary`）→ 🟡（列 host_url）；`double_ext` = true、`is_pe_binary` 的 `.scr`、來自網路的 `.hta`/`.vbs`/`.js` → 🔴。
- 捷徑 `lnk_flags` 含 `download_or_encoded` 或 `lolbin_with_url` → 🔴（假捷徑投遞手法）。
- `.iso`/`.img`/`.lnk` 從網路下載 → 🟡（常見投遞手法）。

## L. 開發者 / AI 代理供應鏈（`dev_supply_chain`）
| 條件 | 嚴重度 |
|---|---|
| `npmrc_has_token` = true | 🟡（npm 蠕蟲會偷；建議改用短效 granular token） |
| `ssh_private_keys` 有 `looks_encrypted` = false | 🟡 |
| `credential_files_present` 有雲端金鑰（.aws/.azure/gcloud/.kube） | 🟡，建議改短效憑證 |
| `.git-credentials` 存在（明文 token） | 🔴 |
| `npm_global_packages` 有不認得的或拼字相近的仿冒名 | 🔴→問 |
| `claude.hooks` 有下載/執行遠端指令（curl、iwr、bash -c 網址） | 🔴 |
| `claude.bypass_or_skip` = true，或 `allow_rules` 含 `Bash(*)`、`Bash`、`PowerShell(*)` | 🟡 |
| MCP server / plugin / marketplace / skills 有使用者不認得的 | 🟡→問 |
| VS Code / Cursor 擴充有不認得或非知名發行者的 | 🟡 |
| `path_user_writable_dirs`（PATH 含可寫目錄）排在 System32 前面 | 🟡 |

## M. 事件紀錄（`event_hints`）
- `failed_logons_7d` > 20 → 🟡（> 200 🔴，可能在被暴力破解，搭配 RDP 開放更嚴重）。
- `defender_detections_7d` 含 1116/1117（偵測到威脅）→ 看是否處理成功；含 5001（即時防護被關）且使用者沒動過 → 🔴。
- `defender_config_changes_7d` 有新增排除路徑或關閉防護、使用者沒動過 → 🔴。
- `ps_scriptblock_warn_7d` 有項目（PowerShell 自動標記為可疑的腳本） → 🔴→查。
