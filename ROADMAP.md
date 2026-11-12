# DFA 熱門工具 Playbook（對標 REA）

## REA 為什麼紅

拆解它的成功要素，每一項都有 DFA 的對應打法：

| REA 的做法 | DFA 對應 |
|---|---|
| 一句話定位："Understand how it works, down to the binary level" | 「丟給 agent 一個 memory image，拿回一份 incident report」— methodology-first，不只是工具包裝 |
| `npx rea-agents setup`，14+ agent 一鍵安裝 | `npx dfa-agents setup` 同等體驗：MCP + skill 一次註冊 |
| 207 個工具，但有組織、有 skill 教 workflow | 先窄後寬：memory → disk → timeline，每個階段都是完整故事 |
| Prompt injection 防禦、EvidenceLedger、schema 相容、deadline 工程 | 三件必做：untrusted content 標記（DFIR 比 RE 更需要）、retained evidence + summary 模式、chain-of-custody + integrity fail-closed |
| Website showcases、20 國語言 README、Discord | Killer demo（GIF/影片）+ 好 README + skills.sh 上架 |
| Known-answer eval、transcript 評分、mutation testing | 公開 eval 分數 — 鑑識圈最吃「信任信號」這套 |

## 差異化：DFA 的三張牌（別處沒有）

1. **方法論層，不是包裝層**。市面上的 Volatility-MCP 只是 thin wrapper。DFA 賣的是六階段鑑識流程、證據＋限制的報告紀律、chain-of-custody。這是 REA "evidence + limitations" 在 DFIR 的版本。
2. **佔領真缺口**。Sleuth Kit / plaso / EVTX 的 MCP 現在是空白 — REA 當年就是靠「把沒人接好的引擎接好」起來的。Memory → disk → timeline 一條龍，別人拼不起來。
3. **與 REA 互補，不是競爭**。DFA 找惡意程式在哪，REA 解釋那段 code 在幹嘛。去 REA Discord 曝光、互相引流，甚至做 interop（malfind 結果直接丟給 REA 分析）。

## 信任：鑑識工具的產品就是信任

- 鑑識結論會被拿去做 incident decision，甚至法律程序。DFA 的每個設計都要能回答："你怎麼證明證據沒被動過？"（custody chain）、"你怎麼知道這不是攻擊者塞給 agent 的指令？"（untrusted 標記）。
- 公開 known-answer eval 分數、CI badge、mutation testing — 讓嚴肅的 practitioner 敢用、敢推薦。

## 發布順序

1. **Memory MVP 打磨**：三件 REA 級工程（untrusted 標記、retained evidence、response budget）+ setup CLI。這是「能紅」的地基。
2. **Eval harness + 公開分數 + demo 影片**：評測即展示，一魚兩吃。
3. **Disk + timeline providers**：佔領缺口，形成一條龍。
4. **發布工程**：README（badges、架構圖、quickstart）、skills.sh、docs 站、社群曝光。

## 誠實的提醒

- **熱門＝維護負擔**。REA 207 個工具＝207 個會壞的東西。先窄後寬，不要一開始就鋪大。
- **不要跟 CrowdStrike / VESTIGEX 拼平台**。DFA 的戰場是 open、local、methodology-first — 這是巨頭不會做、散兵做不好的位置。
- **時機是順風**。Agent + DFIR 還是早期（VESTIGEX 這個月才 beta）。早進場＋品質好＝紅利期。
- 受眾其實比 RE 更大：SOC 分析師、incident responder 是付錢的專業群體，不是只有 hobbyist。
