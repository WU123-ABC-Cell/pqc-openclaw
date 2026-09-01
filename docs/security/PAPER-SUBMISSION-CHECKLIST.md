# PQC Fork Paper Submission Checklist (2026-08-30)

> **目的**: 1-page checklist, 评估 paper 当前是否 ready 提交 (reviewer accept).
> **截至**: 2026-08-30 20:55 北京, 18 commits in WSL local main, 待 push (用户启 FlClash + corp proxy 后).

---

## ✅ 已就绪 (paper-grade)

| 维度 | 当前状态 | 证据 |
|------|---------|------|
| **Side-channel claim** | 7 hot paths × 28 ops × 129.2K ops × max \|t\| < 2.0 | `pqc-fork-scripts/check-cache-timing-claims.sh` (14/14 pass) |
| **User-space timing** | 14 ops × 118K ops (AES-GCM 40K + ML-DSA 18K + ML-KEM 60K) | `pqc-fork-scripts/sidechannel-*.mjs` |
| **Cache-timing** | 14 ops × 11.2K ops (12 ML + 2 AES-GCM), valgrind callgrind | `pqc-fork-scripts/ct-reports/*/report.json` |
| **Algorithm layer PQC-grade** | FIPS 203/204 全部 6 param set KAT 174/174 pass | `pqc-fork-scripts/pqc-kat-bundle.mjs` |
| **M6.B OsKeyring 真部署** | 100% (8/29 验证, byteLength 4032 unwrap OK) | commit `1cdc49a73f` |
| **Whitepaper 主 paper** | 715 行, 5 个时点都同步 8/30 数字 | `docs/security/pqc-whitepaper.md` |
| **Verification log** | 300 行 8/29 + 8/30 验证步骤, 供 reviewer 复现 | `docs/security/verification-log-2026-08-29-30.md` |
| **Paper reviewer FAQ** | 12 Q&A 提前回答 reviewer 质疑 | `docs/security/paper-reviewer-faq.md` |
| **Constant-time self-audit** | 14 ops 全部 0 leak, §5.1.4 14-row table | `pqc-fork-scripts/constant-time-audit.md` |
| **Handoff prompt (2 docs)** | 8/30 增量更新 (M6.B + AES-GCM CT) | `pqc-fork-scripts/pqc-fork-handoff-prompt*.md` |
| **Regression guard** | 14 reports 任何 stale 立即 exit 1 | `pqc-fork-scripts/check-cache-timing-claims.sh` |
| **WSL local main commits** | 22 commits, 8/25-9/1, 全 ready push | `git log --oneline \| wc -l` |
| **作者署名** | 吴昊天 (用户真名) | header **作者:** 字段 |

## ❌ 未就绪 (audit-grade 升级路径, paper 后 backlog)

| 缺口 | 优先级 | 描述 | 估算 |
|------|-------|------|------|
| 第三方 cryptographer 审 | P0 | 4-6 周 + 钱 (50-150K USD) | paper accept 后 |
| mlock Node 24.6+ | P0 | ✅ **code-side done (commit `d8c642df7d`, 9/1)**; Node 24.15+ 升级 + KAT 174/174 + 28 ops 回归仍 2-3 天 | paper accept 后 |
| per-op cache-timing (SIGUSR1/SIGUSR2) | P0 | 14 algo × 5000 ops × 2 class = 98h CPU | 98h |
| 旁路攻击 (EM/power/fault) | P0 | 需专业硬件 + 商业 cryptographer | 4-6 周 |
| AES-NI 硬件 timing | P1 | Intel perf counter 测 | 1 天 |
| ML-DSA-65 inner loop timing | P1 | @noble 0.7.0 实现层 timing | 1-2 天 |
| BoringSSL TLS 1.3 hybrid | P1 | X25519+ML-KEM-768 升级 Gateway TLS | 1 周 |
| HSM 集成 (YubiKey/TPM) | P1 | 企业级 key storage | 1-2 周 |
| FIPS 140-3 正式 cert | long-term | NIST 流程 | 长期 |

## 📋 Pre-submission action items

按"先做不需要 user 介入的"原则, 18 commits 已全部就绪. **仅 1 件需要 user 介入**:

| 行动 | 步骤 | 工时 |
|------|------|------|
| **Push 18 commits → `WU123-ABC-Cell/pqc-openclaw:master`** | 1) 启 FlClash GUI + 装 MITM cert <br/> 2) `git push pqc main:master --force-with-lease -v` <br/> 3) verify GitHub UI 18 commits 出现 | 5-10 min |

**Push 用现有 PAT `18138321`** (DEEPSEEK + 2 PATs revoke 都 deferred 到 PQC fork 收尾后, 8/28 用户明确).

## 🚀 提交路径 (paper-grade 即可)

| 阶段 | 工作 | 当前状态 |
|------|------|---------|
| Push commits | user push 22 commits | ❌ 阻塞 user 启 FlClash |
| 选 paper venue | USENIX Security / IEEE S&P / IACR CHES / IACR TCHES | 待 user 决定 |
| 写 cover letter | 引用 28 ops / 129.2K / 14 reports / 12 Q&A | user 决定 |
| Submit | paper.pdf + supplementary materials (verification log + 14 reports) | 待 user 决定 |

**paper-grade 状态: ready 提交** (audit-grade 4 个 P0 backlog 显式 mark 在 §10 + reviewer FAQ Q3-Q6).

---

**8/30 20:55**: 18 commits in WSL local main, 全 ready push. 阻塞 user 1 步 (FlClash GUI 启 + 5 min push). paper-grade state 完整, audit-grade 4 个 P0 backlog 是 paper accept 后工作, 不阻塞提交.

**9/1 14:30**: +4 commits (`67f1d543eb` cross-ref / `ad963b482e` gitignore / `bd52b85a5f` submission-checklist / `d8c642df7d` mlock), WSL local main 现在 22 commits. M6.B v2 mlock 实施完成 (5 files / 331 ins), Node 22 上 no-op + 单 warning, Node 24+ 锁 wrap key 在物理 RAM. 阻塞 user 1 步 (FlClash GUI 启 + 5 min push).

## 关联文档

- `pqc-whitepaper.md` (主 paper, §5.1.4 / §6.3 / §9.1.2 / §10)
- `paper-reviewer-faq.md` (12 Q&A 提前回答 reviewer 质疑)
- `verification-log-2026-08-29-30.md` (8/29 + 8/30 验证步骤, 复现依据)
- `constant-time-audit.md` (Side-channel 攻击面 §5.1.1-5.1.4 详 14 ops × 0 leak 数据)
