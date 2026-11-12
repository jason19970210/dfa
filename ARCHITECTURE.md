# DFA: Digital Forensics Anything — 架構

> 對標 REA（Reverse Engineer Anything, morluto/rea）的 "One MCP for DFIR"。
> Slogan: **One MCP for DFIR across memory, disk, timeline, and network evidence.**

## 1. 為什麼值得做

- 現況是散的：Volatility-MCP、Velociraptor-MCP、Wazuh-MCP… 各自為政，沒有統一的鑑識方法論、沒有 chain-of-custody、沒有證據完整性保證。
- 已確認的缺口（2026-10-17 調查）：**磁碟鑑識（Autopsy/Sleuth Kit）、sandbox、GRR 都還沒有 MCP server**。
- REA 已驗證的模式可直接複用：單一 MCP tool catalog + skill（workflow 指令）+ setup/doctor CLI + contracts + evaluation harness。
- 本專案的 stack（TypeScript/Node）與 REA 完全一致，可直接借鏡其原始碼結構。

## 2. 對標 REA 的架構

```
dfa/
  src/
    server/            # MCP server, tool catalog 生成
    volatility3/       # provider: 記憶體鑑識 (Volatility 3 CLI 包裝)
    sleuthkit/         # provider: 磁碟鑑識 (fls/icat/mmls/fsstat, 唯讀掛載)
    plaso/             # provider: super-timeline (log2timeline + psort 查詢)
    yara/              # provider: YARA 規則管理 + 掃描
    evtx/              # provider: Windows 事件日誌解析
    registry/          # provider: registry hive 解析
    tshark/            # provider: pcap 分析 (可借鏡 REA 的 pcap 實作)
    velociraptor/      # provider: VQL triage (選配, 需 server)
    intel/             # provider: VT/MISP/ATT&CK 富化 (能復用社群 MCP 就不重造)
    custody/           # chain-of-custody: 每次 tool call 的 hash-chained audit log
    contracts/         # 工具結果/證據輸入/scope 契約 (對標 REA docs/mcp-contracts.md)
    setup/             # npx dfa-agents setup --client <claude_code|codex|cursor...>
    doctor/            # 診斷註冊/引擎可用性
    evaluation/        # 合成 DFIR 場景迴歸測試 (見 §5)
  skills/
    dfir-investigate/
      SKILL.md         # 何時用 DFA、六階段方法論、證據紀律
      references/
        methodology.md        # 識別→蒐集→檢驗→分析→時間軸→報告
        memory-forensics.md
        disk-forensics.md
        timeline-analysis.md
        windows-artifacts.md
        chain-of-custody.md
  bridge/              # 需要時：在鑑識工具內執行的橋接腳本 (對標 REA bridge/)
  docs/
```

## 3. 核心設計原則（從 REA 借來，DFIR 版加強）

1. **證據唯讀**：所有 provider 預設唯讀；寫入操作需要明確 scope 授權。掛載磁碟映像一律 read-only loop。
2. **證據 + 限制**：每個結論附證據與限制（REA 的 evidence discipline），鑑識報告禁不起「好像是」。
3. **Chain of custody**：每次工具呼叫記錄輸入 hash → hash-chained audit log，可匯出 HTML/PDF 報告（VESTIGEX 已證明這是剛需）。
4. **Scope contracts**：工具呼叫前聲明作用域與本地影響（對標 REA mcp-contracts.md 的 Request scope and local effects）。
5. **本地分析**：證據不上雲；富化查詢（VT）才走網路，且明確標示。

## 4. 與現有生態的關係（不重造輪子）

- 富化層直接復用社群 MCP（VirusTotal、MISP、ATT&CK）。
- 缺口處自己造：Sleuth Kit provider、plaso provider、evtx provider 目前都沒有好的 MCP。
- REMnux-mcp 的 `suggest_tools` 概念可借鏡：依證據類型推薦分析鏈。

## 5. Evaluation harness（技術含量的關鍵）

合成可重現的 DFIR 場景，迴歸測試 agent 的調查品質：
- 記憶體映像（含 process injection）→ agent 應找出惡意 process + C2 IP
- EVTX（含橫向移動）→ agent 應重建時間軸
- 磁碟映像（含刪除檔案）→ agent 應恢復並計算 hash
每個場景有 ground truth，CI 自動評分。這是 REA `src/evaluation/` 的 DFIR 版，也是 repo 最有說服力的部分。

## 6. MVP 選項（2026-10-17 選定 A）

- **A. Memory-first** ✅ SELECTED：Volatility 3 provider + dfir-investigate skill + custody log。最自包含，demo 路徑最短（一個 memory dump → agent 找出 injected process）。 scaffold 已建成（見 §8）。
- **B. Triage+timeline-first**：plaso + evtx + yara providers。覆蓋面廣但每個都薄。
- **C. Skeleton-first**：完整 repo 骨架（MCP server、setup/doctor、skill、contracts、eval harness），provider 先留 stub。最快有「像樣的 repo」形狀，再逐一填肉。

## 8. 實作現況（2026-10-17）

- `dfa-agents` npm 套件骨架：`src/main.ts`（serve/doctor CLI）、`src/server/`（MCP server，11 個 tools）
- `src/volatility3/Volatility3Client.ts`：allow-list 12 個 plugin，唯讀執行 + JSON 解析 + image SHA-256
- `src/custody/CustodyLog.ts`：hash-chained JSONL audit log，`verify()` 可偵測竄改（vitest 3 tests 通過）
- `skills/dfir-investigate/`：SKILL.md + references/memory-forensics.md
- 驗證：`npm run build` 通過；Volatility 3 Framework 2.28.2（venv）；MCP stdio smoke test 通過（tools/list、dfa_doctor、isError 錯誤回傳、DFA_EVIDENCE_DIR allowlist）
- **2026-10-17 新增 report generator**：`src/report/ReportGenerator.ts` — 自包含 HTML 鑑識報告（零外部資源，可列印成 PDF）：案件資訊、證物清單、chain-of-custody 時間軸、方法、發現、限制六章節＋完整性橫幅（intact/broken）。custody record 新增 `detail` 明文字段（納入 hash）。MCP tool `dfa_report_generate` + CLI `dfa-agents report --out/--verify`。vitest 6 tests 全過，MCP + CLI 端到端驗證通過。
- 待辦：eval harness、demo memory image、setup CLI

## 7. 待定

- 正式命名（DFA / DIRA / 其他）
- License：MIT（已定，見 LICENSE）
