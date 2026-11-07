---
name: pc-security-scan
description: 全面檢查這台 Windows 電腦的資安風險（唯讀、不改任何設定）：Windows 更新與修補、防毒/Defender 狀態與排除清單、防火牆、UAC/BitLocker/Secure Boot/SMBv1/RDP 等強化設定、本機帳號與管理員、開機自動啟動（Run 機碼、啟動資料夾、排程工作、服務、WMI、IFEO）、可疑或未簽章的執行中程式、對外開放的連接埠與外連、共用資料夾、DNS/Proxy/hosts/自訂根憑證、已安裝軟體、瀏覽器擴充功能權限、下載資料夾近期執行檔、開發者供應鏈（npm token、SSH 金鑰、Claude Code hooks/MCP/plugin、VS Code 擴充），最後依嚴重度產出報告與修正步驟。觸發時機：使用者說「掃描電腦安全」「電腦資安健檢」「檢查電腦有沒有中毒」「看電腦有沒有後門」「檢查開機啟動項」「電腦危險性」「最近資安事件很多幫我檢查」，或輸入 /pc-security-scan。不要觸發：掃描別人的電腦或網路、家用網路/路由器檢查（用 home-network-audit）、程式碼漏洞（用 vuln-scan-fix）、要求繞過防毒或隱藏程式、macOS/Linux（本 skill 只支援 Windows）。
---

# 電腦資安健檢（Windows）

本 skill 目錄（下稱 SKILL_DIR，就是系統顯示的 base directory）裡有：
- `scan.ps1`：唯讀蒐集腳本，輸出一份 JSON
- `checklist.md`：判讀規則與嚴重度，評分照這張表

全程用繁體中文回報。每做完一段用一兩句話告訴使用者進度。

## 0. 界線

- **只檢查、不修改**。任何修正（停用啟動項、刪檔、改設定、解除安裝）都要列出來、逐項問使用者，使用者同意後才做；能讓使用者自己點的就給「在哪個選單、改成什麼」。
- 不讀取、不顯示任何密碼或金鑰內容：腳本只檢查憑證檔「存在與否」、SSH 金鑰「有沒有加密」，不跑 `netsh wlan ... key=clear`，不讀 Winlogon DefaultPassword 的值。
- 不上傳任何掃描結果。要查某個檔案的信譽時，只用雜湊值（SHA256）或檔名查詢，不上傳檔案本身；查詢前先問使用者。
- 只掃這台電腦。

## 1. 執行掃描

1. 問一句：「要用系統管理員權限跑嗎？用管理員能多看 BitLocker、Defender 排除清單、WMI 持久化、登入失敗紀錄；不用也能跑大部分項目。」
   - 使用者要管理員：請他自己開「以系統管理員身分執行」的 PowerShell 貼指令跑（Claude 不自行提權）。
   - 不要：Claude 直接跑。
2. 指令（約 1–4 分鐘；簽章檢查最慢，趕時間加 `-Quick`）：
   ```
   powershell -NoProfile -ExecutionPolicy Bypass -File "SKILL_DIR\scan.ps1" -Out "<scratchpad>\pc-scan.json"
   ```
   用背景執行或 timeout 給 600000。實測一般筆電約 20–40 秒。進度寫在 stderr（`[scan] xxx done`），結果檔約 150–300 KB。
   `scan.ps1` 必須是 UTF-8 **含 BOM**（Windows PowerShell 5.1 才不會把中文字串讀壞）；編輯後要重存成含 BOM。
3. JSON 很大，不要整份印進對話。用 PowerShell 讀檔 `Get-Content ... -Raw -Encoding UTF8 | ConvertFrom-Json`，分段取需要的欄位（例如 `autoruns.entries` 只看 `flags` 非空或簽章非 Valid 的）。自己寫的讀取腳本也要加 `-ExecutionPolicy Bypass` 執行。
4. 值是 `needs_admin` 的項目在報告裡列成「未檢查（需管理員）」，不要當成通過或失敗。

## 2. 判讀

照 `SKILL_DIR/checklist.md` 逐節判讀。重點：

- 腳本的 `flags` 只是線索，Claude 要自己判斷：知名廠商簽章（Google、Microsoft、Adobe、NVIDIA…）放在 AppData 很常見（Chrome、Teams、Discord、OneDrive 都是），不要誤報成病毒。
- 真正值得🔴的組合：**未簽章或簽章無效 + 使用者可寫路徑 + 開機自動啟動**、啟動命令含 base64/下載指令、Defender 被關或有奇怪排除路徑、未知 IFEO debugger、非預期的根憑證、Proxy/PAC 指向陌生位址、hosts 把銀行或更新網站導走。
- 已安裝軟體：挑出常被攻擊的（瀏覽器、7-Zip、WinRAR、Java、Adobe Reader、Zoom、AnyDesk/TeamViewer 等遠端工具、VPN 用戶端、Node.js、Python、Git），對照目前版本；Claude 不確定最新版或已知漏洞時，用 WebSearch 查證，不要憑記憶下結論。
- 瀏覽器擴充：`risky_permissions` 含 `<all_urls>`/cookies/webRequest 且不是來自官方商店（`from_store: false`）或使用者不認得的，列🟡請使用者確認。
- 開發者/AI 代理供應鏈：npm 全域套件、`.npmrc` token、無密碼 SSH 金鑰、Claude Code 的 hooks 指令、MCP server、第三方 marketplace、`permissions.allow` 過寬（例如 `Bash(*)`）都要列出，請使用者確認每一個都是自己裝的。
- 對外開放埠：列出非本機監聽的 TCP 埠與程式，標出 RDP(3389)、SMB(445)、WinRM(5985/5986)、SSH(22)、資料庫埠、開發伺服器（3000/5000/8000/8080 綁 0.0.0.0）。
- 不認得的項目逐一問使用者，不要自己斷定是惡意。

## 3. 報告

1. 先在對話給 5 行內摘要：整體燈號 + 🔴 幾項 / 🟡 幾項 / 🟢 幾項 + 最該先處理的三件事。
2. 完整報告用 Artifact 發一頁 HTML（先載入 artifact-design skill），或使用者要檔案就寫 `PC_SECURITY_REPORT.md`。結構：
   - 總覽燈號與分數（照 checklist.md 計分）
   - 🔴 立即處理：每項寫「發現什麼 → 為什麼危險 → 怎麼修（具體選單路徑或指令）」
   - 🟡 建議處理 / 需要你確認
   - 🟢 已做好的項目（簡短列）
   - 附錄：開機啟動項、對外埠、擴充功能、軟體清單
   - 註明哪些項目因沒有管理員權限而未檢查
3. 最後用一個問題問使用者要先處理哪幾項；同意後一次做一項、做完回報，可逆的做法優先（停用而不刪除、移到隔離資料夾而不永久刪除）。

## 4. 疑似中毒時

出現高度可疑項目（未簽章程式從 Temp 開機啟動、Defender 被關且有排除、陌生根憑證 + Proxy）時：
- 先建議：拔網路線/關 Wi-Fi、用另一台乾淨裝置改重要帳號密碼並開兩步驟驗證。
- 建議跑 Microsoft Defender 離線掃描（Windows 安全性 → 病毒與威脅防護 → 掃描選項 → Microsoft Defender 離線掃描），會重開機。
- 不要自己刪檔；先記錄路徑與 SHA256（`Get-FileHash`），問使用者後再處理。
