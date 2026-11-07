# pc-security-scan：Windows 電腦資安健檢 skill

讓 Claude Code 全面檢查一台 Windows 電腦的資安風險，依嚴重度排序後產出報告和修正步驟。

- **只讀不改**：掃描過程不動任何設定、不刪檔、不裝東西。
- **不碰機密**：不讀密碼、金鑰、Wi-Fi 密碼的內容，只看檔案存不存在、金鑰有沒有加密。
- **不上傳**：掃描結果只存在本機。
- **修正要你點頭**：報告列出問題後，一項一項問你，同意才動手。

---

## 檢查項目

| 類別 | 看什麼 |
|---|---|
| 系統修補 | Windows 版本、最近一次安裝更新的日期、是否等待重開機、更新是否被暫停 |
| 防毒 | 安裝了哪些防毒、Defender 即時防護/竄改防護/雲端防護、病毒碼幾天沒更新、排除清單、最近偵測到的威脅 |
| 防火牆 | 各網路設定檔是否開啟、預設是否擋輸入連線、目前網路被設成公用還是私人 |
| 系統強化 | UAC、RDP 與 NLA、SMBv1、BitLocker、Secure Boot、TPM、VBS/HVCI、LSA 保護、遠端登錄、WinRM、OpenSSH 伺服器、PowerShell 2.0、執行原則、SmartScreen |
| 帳號 | 管理員群組成員、Guest/內建 Administrator 是否啟用、自動登入、明文自動登入密碼（只看有沒有，不讀值） |
| 開機自動啟動 | Run/RunOnce 機碼、啟動資料夾、非微軟的排程工作、非系統服務、WMI 事件訂閱、IFEO debugger、Winlogon Shell/Userinit、AppInit_DLLs |
| 執行中程式 | 不在 `C:\Windows` 底下的程式：數位簽章、是否在使用者可寫的資料夾、命令列有沒有 base64 或下載指令 |
| 網路暴露 | 對外監聽的 TCP/UDP 埠與對應程式、對外連線、共用資料夾與權限 |
| 網路設定 | DNS、系統 Proxy/PAC、WinHTTP Proxy、hosts 檔（區分「封鎖」和「導向別的 IP」）、非知名 CA 的根憑證、會自動連線的開放 Wi-Fi |
| 已安裝軟體 | 完整清單、最近 30 天新裝的軟體 |
| 瀏覽器擴充 | Chrome、Edge、Brave、Firefox：名稱、版本、高風險權限（所有網站、cookies、webRequest、debugger…）、是否來自官方商店 |
| 近期下載 | 下載、暫存、桌面等資料夾近 14 天的執行檔、腳本、捷徑、映像檔：是否從網路下載、來源網址、簽章、雙副檔名、捷徑實際指向 |
| 開發者供應鏈 | 雲端憑證檔、`.npmrc` token、`.git-credentials`、沒加密的 SSH 私鑰、npm 全域套件、VS Code/Cursor 擴充、PATH 中可寫目錄 |
| AI 代理 | Claude Code hooks、權限 allow 規則、是否開啟略過權限、plugin、marketplace、MCP server、個人 skills |
| 事件紀錄 | 近 7 天：登入失敗次數、新安裝的服務、Defender 偵測、Defender 排除清單或防護被關的變更、PowerShell 自動標記的可疑腳本 |

---

## 安裝

把整個 `pc-security-scan` 資料夾複製到個人 skills 目錄：

```powershell
Copy-Item -Recurse .\pc-security-scan "$env:USERPROFILE\.claude\skills\"
```

裝好後的結構：

```
%USERPROFILE%\.claude\skills\pc-security-scan\
├── SKILL.md       給 Claude 的流程與界線
├── scan.ps1       唯讀蒐集腳本（UTF-8 含 BOM）
├── checklist.md   判讀規則、嚴重度、已知誤報
└── README.md      本說明
```

需求：Windows 10/11，內建的 Windows PowerShell 5.1 即可，不用裝 Python 或其他套件。

---

## 使用方式

在 Claude Code 裡說以下任一句，或輸入 `/pc-security-scan`：

- 「電腦資安健檢」
- 「掃描電腦安全」
- 「檢查電腦有沒有中毒」
- 「看電腦有沒有後門」
- 「檢查開機啟動項」

Claude 會先問要不要用系統管理員權限跑：

| 模式 | 怎麼跑 | 差別 |
|---|---|---|
| 一般權限 | Claude 直接執行 | 大部分項目都能檢查 |
| 系統管理員 | Claude 給指令，你自己開「以系統管理員身分執行」的 PowerShell 貼上 | 多看 BitLocker、TPM、Defender 排除清單、WMI 持久化、登入失敗紀錄 |

Claude 不會自己提權。一般權限下看不到的項目，報告會標成「未檢查（需管理員）」，不會算成通過。

### 單獨執行腳本

不透過 Claude 也能跑，結果是一份 JSON：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "$env:USERPROFILE\.claude\skills\pc-security-scan\scan.ps1" -Out "$env:TEMP\pc-scan.json"
```

| 參數 | 說明 |
|---|---|
| `-Out <路徑>` | 必填，JSON 輸出位置 |
| `-Quick` | 略過數位簽章檢查，速度較快，但少了簽章資訊 |

一般電腦約 20–60 秒跑完，輸出約 150–300 KB。進度會印在 stderr，例如 `[scan] autoruns done 3.1s`。

---

## 報告長什麼樣

Claude 先在對話中給五行內的摘要，再產出完整報告（HTML 頁面，或依你要求寫成 `PC_SECURITY_REPORT.md`）。

**分級與計分**

- 🔴 高風險，立即處理（每項扣 10 分）
- 🟡 建議處理，或需要你確認（每項扣 3 分）
- 🟢 正常
- 滿分 100：90 分以上良好，70–89 普通，70 以下需要處理

**每個問題的寫法**：發現什麼 → 為什麼危險 → 怎麼修（具體的選單路徑或指令）。

示意（虛構範例）：

> 🔴 **開機自動執行未簽章程式**
> 發現：`HKCU\...\Run` 有一筆 `SysHelper`，指向 `C:\Users\<你>\AppData\Local\Temp\svchelper.exe`，沒有數位簽章。
> 為什麼危險：正常軟體很少從暫存資料夾開機啟動，這是木馬常見的持久化手法。
> 怎麼修：先記錄檔案 SHA256 → 工作管理員「啟動應用程式」停用 → 跑 Defender 離線掃描 → 確認後再刪除。

> 🟡 **SSH 私鑰沒有密碼保護**
> 發現：`~\.ssh\id_ed25519` 未加密。
> 為什麼危險：電腦被植入竊密程式時，金鑰會直接被拿走。
> 怎麼修：`ssh-keygen -p -f ~\.ssh\id_ed25519` 加上密碼。

---

## 判讀原則

腳本只蒐集線索（`flags`），最後由 Claude 綜合判斷，避免把正常軟體報成病毒：

- 知名廠商有效簽章的程式放在 AppData 很常見（瀏覽器更新程式、通訊軟體、雲端硬碟），不算可疑。
- 真正要警覺的是**多個訊號同時出現**：沒簽章、在使用者可寫的資料夾、會開機自動啟動、命令列有 base64 或下載指令。
- 軟體版本有沒有已知漏洞，Claude 會上網查證，不憑記憶下結論。
- 認不出來的項目會問你，不會直接斷定是惡意程式。

`checklist.md` 第 0 節列出常見誤報，例如：

- 防火牆 `NotConfigured` 等於預設封鎖
- 市集 App 顯示 NotSigned 是因為用目錄簽章
- `.scr` 檔若不是執行檔格式（例如 AutoCAD 腳本）就不是螢幕保護程式
- Defender 事件 5007 每天出現多次是例行更新

---

## 疑似中毒時

報告出現高度可疑的組合時（例如暫存資料夾的未簽章程式開機啟動，且 Defender 被關閉或多了奇怪的排除路徑），Claude 會建議：

1. 先斷網（拔網路線或關 Wi-Fi）。
2. 用另一台乾淨的裝置改重要帳號密碼，並開啟兩步驟驗證。
3. 跑 Microsoft Defender 離線掃描：Windows 安全性 → 病毒與威脅防護 → 掃描選項 → Microsoft Defender 離線掃描（會重開機）。
4. 可疑檔案先記錄路徑和 SHA256，不急著刪，確認後再處理。要查檔案信譽時只送雜湊值，不上傳檔案本身，而且會先問你。

---

## 限制

- **只支援 Windows**，macOS、Linux 不適用。
- **不是防毒軟體**：不做特徵碼比對、記憶體掃描或 rootkit 偵測，看的是設定和常見入侵痕跡。乾淨的報告不代表 100% 沒中毒。
- **只看這台電腦**：家用網路和路由器請用 `home-network-audit`，程式碼漏洞請用 `vuln-scan-fix`。
- 近期下載只掃三層資料夾、每個資料夾最多 40 個檔案。
- 事件紀錄只看最近 7 天。
- 根憑證用知名 CA 名稱過濾，冷門但合法的 CA 可能被列出，需要人工確認。

---

## 修改腳本時注意

- `scan.ps1` 含中文字串，必須存成 **UTF-8 含 BOM**，否則 Windows PowerShell 5.1 會讀成亂碼並出錯。
- 每個檢查段落用 `Try-Run` 包起來，單一段落失敗只會在該欄位留下 `error`，不會讓整份掃描中斷。
- 輸出前會用 `Norm` 把所有值轉成純字串和數字。PowerShell 5.1 的 `ConvertTo-Json` 遇到 `Get-Content` 讀出的字串會展開隱藏屬性，可能卡住好幾分鐘、吃掉上 GB 記憶體。
- 會丟出終止例外的指令（例如 `Confirm-SecureBootUEFI`、`Get-AuthenticodeSignature` 遇到沒權限的檔案）要個別包 `try/catch`，`-ErrorAction SilentlyContinue` 擋不住這類錯誤。
