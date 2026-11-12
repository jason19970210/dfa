# DFA Eval Scenarios（初版草稿）

> 設計原則：每個 scenario 都能在受控 Linux VM 裡「演出來」；
> 演出腳本化 → ground truth 自動產生；全部走 memory forensics 可偵測的 artifacts。
> 前置條件：DFA 需先加入 linux.* plugin 支援（與 windows.* 同一條 pipeline，約數十行）。

## Tier 1 — Triage 基本功

### S1. 挖礦木馬（Cryptominer）
- **故事**：伺服器被植入 xmrig，對外連礦池。
- **演出**：跑 miner 連測試礦池（本地 fake pool 也行）、加 cron 持久化。
- **Memory artifacts**：miner process（pslist）、礦池連線（netscan）、cmdline 參數、cron。
- **Ground truth**：process 名/PID、礦池 IP:port、cron 內容。
- **測什麼**：基本 triage — pslist + netscan 關聯出「誰在對外連線」。

### S2. Reverse shell / C2 beacon
- **故事**：入侵後拿到 reverse shell，定時 beacon 回連。
- **演出**：python reverse shell 連回本地 listener，sleep 迴圈模擬 beacon。
- **Artifacts**：異常 parent-child（pslist/pstree）、ESTABLISHED 連線（netscan）、bash history。
- **Ground truth**：C2 IP:port、shell PID、完整 parent chain。
- **測什麼**：process tree 解讀＋network 關聯，IR 最常見的起手式。

## Tier 2 — 技術專項

### S3. Fileless 注入（memfd_create）
- **故事**：無檔案惡意程式，payload 只活在記憶體，磁碟上什麼都沒有。
- **演出**：python loader 用 memfd_create 建匿名檔案、寫入 payload 後執行。
- **Artifacts**：process exe 指向 `/memfd:`（已刪除）、linux.malfind 命中、匿名可執行區段。
- **Ground truth**：memfd 名稱、malfind 命中的 PID/VPN。
- **測什麼**：進階 injection 偵測；「磁碟乾淨≠乾淨」的觀念。

### S4. Web shell
- **故事**：網站被植入 web shell，攻擊者遠端下指令。
- **演出**：簡易 HTTP server 接受 `?cmd=` 執行，下 whoami、cat /etc/passwd 等指令。
- **Artifacts**：web server 的可疑子行程、cmdline、bash history、來源 IP 連線。
- **Ground truth**：webshell PID、執行的指令序列、攻擊者 IP。
- **測什麼**：server compromised 情境、子行程血緣分析。

### S5. 勒索軟體模擬
- **故事**：勒索軟體加密文件目錄、留下勒索信。
- **演出**：script 遍歷目錄加密、寫勒索信、刪除備份快照。
- **Artifacts**：加密行程、大量檔案活動、勒索信檔案、可疑 cmdline。
- **Ground truth**：加密行程 PID、被加密檔案數、勒索信路徑。
- **測什麼**：影響範圍評估（blast radius），IR 最常見的實戰題。

## Tier 3 — 綜合推理

### S6. 內鬼資料外洩（Insider exfil）
- **故事**：內部人員打包機密資料外傳，並清除 bash history 滅證。
- **演出**：tar 打包 /data、curl 上傳到外部 server、`history -c` 清除。
- **Artifacts**：tar/curl 行程、上傳連線、**被清空的 history 本身就是線索**（memory 中可能還殘留）。
- **Ground truth**：打包檔案清單、外傳 IP:port、時間窗。
- **測什麼**：綜合推理＋anti-forensics：agent 能否注意到「history 被清掉」這個反常？

---

## Pre-test：fixture 上線前的驗證

Fixture = {image, ground_truth.json, expected_findings}。上線前必須通過：

1. **演出腳本化**：攻擊步驟寫成 script，執行同時輸出 ground_truth.json（PID、IP、port、時間戳、路徑）。Ground truth 是演出的副產品，不是事後人工整理的 — 這是 known-answer eval 可信的根基。
2. **Volatility 可見性檢查**：dump 後手動跑對應 plugin，確認 artifact 真的看得到。看不到＝fixture 無效，打掉重演，不要硬拗。
3. **Negative control**：同一 VM 乾淨狀態 dump 一份 baseline。Agent 應該回報「無發現」— 測 false positive率。
4. **穩定性**：同一 fixture 跑兩次分析，結果一致；記錄各 plugin 執行時間（CI 時間預算）。
5. **盲測**：不看 ground truth，先讓 agent（或人）完整調查一遍，再對分。分數＝eval harness 的第一個數據點。
6. **大小檢查**：目標 ≤512MB。超過就檢討（RAM 配額、dump 範圍）。

## 與 eval harness 的關係

每個 scenario 對應 REA 式 KnownAnswerEvaluation 的一組 fixture：
fixture claim = {預期值、來源 operation、confidence}，失敗類型沿用
claim_missing / value_mismatch / source_*_mismatch。S1–S2 先行，S3–S6 逐步加入。
