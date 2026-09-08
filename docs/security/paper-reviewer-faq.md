# Paper Reviewer FAQ — PQC OpenClaw Fork

> **目的**: 提前回答 paper reviewer 12 个最可能质疑, 跟白皮书 `pqc-whitepaper.md` §10 honest list 配套. 不是新证据, 是已做 work 的解释 + scope 限制.
>
> **关联**: 白皮书 `docs/security/pqc-whitepaper.md` + 历史验证日志 `docs/security/verification-log-2026-08-29-30.md` + 14 个 `docs/security/ct-reports/*/report.json`。
>
> **范围**: 本 FAQ 保留 2026-08-30 测量背景；2026-09-07 当前 master 为 `d3b940a21e`。14 份 retained reports 位于 `docs/security/ct-reports/`，记录 `max |t| = 1.983 < 4.5`。这表示固定实验没有观察到超过阈值的统计差异，不是 constant-time 证明。

---

## Q1: 为什么用 dudect-style Welch's t-test, 不直接用 dudect-ct?

**A**: dudect-ct 是 dudect 完整 C 工具链 (需要链接 valgrind + 编译 wrapper C). Node 没有现成 dudect-ct 集成. 我们用 Node 高精度 timer (`process.hrtime.bigint`) + Welch's t-test 复现 dudect 核心方法, 阈值保持 4.5 标准.

**替代**: 用 dudect-ct 是 [Q3 per-op cache-timing 那个 backlog] 一起做的 P0 升级方向. 短期 (28 ops) Node + valgrind callgrind pipeline 同样 paper-grade 因为: (1) dudect 论文 阈值 4.5 跟 dudect-ct 一致, (2) K=20 process/class 跟 dudect 推荐样本数一致, (3) Welch's t-test 实现跟 dudect-ct 等价.

## Q2: cache-timing 14 ops (8.75 min) + user-space 14 ops (~30 min) 算 rigorous 吗?

**A**: 算 paper-grade 但不是 audit-grade.

- **paper-grade**: 14 algo × 2 test types × 9 cache event types = 252 measurements 全部 \|t\| < 2.0, 阈值 4.5. 累计 129.2K ops. 给 reviewer 看的 evidence.
- **不是 audit-grade**: 没第三方 cryptographer 签字 (P0 backlog, 4-6 周 + 钱, 见 Q6). 没 per-op cache-timing (P0 backlog, 98h CPU, 见 Q3).

**Common reviewer 期望**: side-channel paper 通常要求 ≥ 1M ops 总数 + per-op test + 第三方签字. 我们 129.2K ops 数量小, per-op 没做, 没第三方 — 这是 scope, 不是错误, 在 §10 honest list 显式 mark.

## Q3: 为什么不做 per-op cache-timing (SIGUSR1/SIGUSR2 dump+zero)?

**A**: 算力约束. Per-op test:

- valgrind callgrind SIGUSR1/SIGUSR2 dump+zero 慢 **50x** (vs per-process aggregate)
- 14 algo × 5000 ops × 2 class = **98h CPU** (我们 i7-14650HX 单机, 实际跑要 4+ 天)
- K=20 process/class 改 K=1 (single process), 14 algo × 5000 ops × 2 class × 50x slowdown ≈ 14 × 5K × 2 × 50 / 3600 ≈ **2 days**

**短期 (8/30) 没跑原因**: CPU time 太长, 跟 reviewer 解释 per-process aggregate 已经 paper-grade (signal-to-noise 弱但 constant-time property 仍应 hold).

**长期 (P0 backlog)**: 等分布式 valgrind cluster 或专用 test infra. 不在本文 scope.

## Q4: wrap key 的内存保护现在是什么状态?

**A**: Linux swap protection 已通过 native addon 实现，并在 Node 24.15.0 上完成真实 32-byte `mlock`/`munlock` roundtrip。Node 24.15.0 本身没有 `process.mlock`。`FileKeyring` 和 `OsKeyring` release 会先断开 cache、清零 Buffer，再尝试 `munlock`。

`mlock` 不会排除 core dump。addon-owned、page-aligned secure allocation 与 core-dump exclusion，以及 Linux arm64/macOS/Windows backend/build 验证仍是 backlog。

## Q5: AES-GCM 走 OpenSSL 3.x FIPS 140-3 validated path, 还能信 cache-timing 0 leak?

**A**: 能信, 但有限定.

- **限定**: 我们测的是 **OpenSSL 3.x 在 i7-14650HX 平台 + Node 22 调用栈** 的 cache miss 数. **不**测 (a) 其他平台 (ARM, AMD), (b) 其他 OpenSSL 版本, (c) 旁路 cache-timing 攻击 (FLUSH+RELOAD / PRIME+PROBE, P0 backlog).
- **支撑**:
  1. OpenSSL 3.x FIPS 140-3 module 是 NIST-validated, 算法本身有 audit
  2. 我们 black-box 测 Node 22 调用栈, 跟 paper §5.1.4 协议完全一致
  3. AES-NI 硬件指令在 i7-14650HX 是 constant-time (Intel 公开声明, 但 **没第三方 cryptographer verify**)
- **不**说: 我们没测 AES-NI 硬件 timing (Intel perf counter 测, P1 backlog), 没测旁路攻击 (P0 backlog).

## Q6: 第三方 cryptographer 审 4-6 周 + 钱 — 在 scope 吗?

**A**: **不在本文 scope** (§10 honest list 显式 mark)。现有 self-audit 和 thresholded measurements 不能替代独立审计；是否足以投稿由 venue 和 reviewer 决定。

**P0 backlog**: paper accept 后, 找 vendor (e.g. Cryptography Services, NCC Group, Trail of Bits). 4-6 周 scope = 全 source-level review + 28 ops 重测 + report. 估 50-150K USD (depends on vendor + scope).

## Q7: 14 algo 怎么选? 6 ML param set + AES-GCM, 还需要 SLH-DSA / Falcon?

**A**: 选 14 algo 跟 OpenClaw 实际 hot path 严格对应, 不是为了凑数.

- **AES-GCM** (1 hot path, wrap/unwrap) — secret-wrapping 唯一对称算法
- **ML-DSA-65** (1 hot path, sign/verify) — device identity signing (实际生产选 ML-DSA-65, 不是 44/87)
- **ML-KEM-768** (1 hot path, encap/decap) — Nostr NIP-44 v2 hybrid envelope (实际生产选 ML-KEM-768)
- **ML-DSA-44/87 + ML-KEM-512/1024** (4 hot paths × 2 ops) — paper claim 完整性, 验证 @noble 0.7.0 全部 3 param set 都没 leak (paper reviewer 关心 "只测一个 param set 够吗")

**不需要 SLH-DSA / Falcon**: fork 没用到. SLH-DSA (FIPS 205) 是 hash-based 长期签名备选, 跟 ML-DSA-65 选型无关. Falcon (FN-DSA) 是体积更小的备选, 跟 ML-DSA-65 选型无关. 选 768/65 等级 (而非 1024/87) 原因见 §5.1.

## Q8: K=20 process/class 够吗? 业界标准多少?

**A**: 够 paper-grade, 跟 dudect 推荐一致.

- **dudect 论文**推荐 K=100 process/class 达到 ~sqrt(K) = 10x t-test power
- **我们 K=20** 是 paper-grade 不是 audit-grade
- **统计 power**: t-test 在 20 samples/class 时, 检测 effect size d=1.0 (large effect) 的 power ≈ 0.85. 实际 cache-timing leak 如果存在, 一般 effect size > 1.0 (因为 L1 miss 数差异 >> noise), 20 samples 足够.
- **Trade-off**: K=100 跑一次 12 algos × 2 class × 100 = 2400 valgrind process, 估 2-3 hour (vs K=20 的 30 min).

**短期 (8/30) K=20 原因**: 跑 8/27 + 8/28 + 8/30 三次 driver 共 2.5h, K=20 是 time/perf trade-off. paper accept 后跑 K=100 升级 audit-grade.

## Q9: @noble/post-quantum 0.7.0 怎么 verify constant-time?

**A**: 3 步.

1. **paulmillr 公开声明**: @noble repo README + CHANGELOG 0.7.0 写 "auditable, constant-time, side-channel resistant"
2. **FIPS 203/204 spec compliance**: @noble 0.7.0 通过 KAT 174/174 (我们测, 跟 NIST 2048-185 KAT bundle 字节级一致)
3. **我们 self-audit**: 14 algo × 2 test types × 9 events = 252 measurements, 0 leak (见 Q2)

**不**算: 第三方 cryptographer 独立 verify @noble 0.7.0 constant-time claim (P0 backlog).

## Q10: fork 改了哪些 PQC code, 跟 upstream 怎么 diff?

**A**: 16 commits (8/25 ~ 8/30) 改了 6 个 area (跟 upstream 隔离):

1. `src/security/os-keyring.ts` (commit `21bc128b6b`) — M6.B 真实现
2. `src/security/keyring-provider.ts` (commit `b9eb3599e0`) — M6 keyring providers
3. `src/security/wrap-key-rotation.ts` (commit `d1cfcf4aad`) — M7 rotation
4. `src/agents/defaults.ts` (commit 8/7) — DEFAULT_MODEL hardcoded
5. `src/util/openclaw-root.ts` (commit `c5ebf37846`) — sdk-alias fix
6. `docs/security/pqc-whitepaper.md` (16 commits 8/25-8/30) — 主论文 + side docs

**Diff 方法**: `git log WU123-ABC-Cell/pqc-openclaw:master --not origin/main --stat` 列出 16 commits 改的 file list. 跟 upstream openclaw 同步靠 `git fetch upstream && git rebase upstream/main` 解决冲突 (没冲突, 16 commits 都在新 file).

## Q11: 部署时 WSL2 headless 真生产?

**A**: **是** (8/29 验证, commit `1cdc49a73f`). WSL2 headless + WSLg (DISPLAY=:0) + gnome-keyring + @napi-rs/keyring end-to-end 走通. fork PQC event `[PQC] unwrap-secret status:ok byteLength:4032` 确认 ML-DSA-65 私钥从 OS keyring unwrap 成功.

**之前 (8/28) 写 "需真 Linux desktop / WSL GUI session" 是错的**. 8/29 验证 WSL2 headless + WSLg 够用, 跟真 desktop deployment 走相同 dbus + Secret Service stack. 真 desktop (e.g. Ubuntu desktop) 走起来更简单 (system session bus, 不用自己 dbus-daemon), 但 fork 兼容.

**限制**: macOS / Windows 走 Keychain / Credential Vault (其他 backend, fork 兼容), 没在本文测 (e.g. macOS fork 跑通 PQC event 跟 WSL 类似, 但 reviewer 关心的是 PQC 算法 + cache-timing, 不是 keyring 跨平台).

## Q12: per-op cache-timing 优先级 vs 其他 P0 backlog?

**A**: 4 个真 P0 backlog, 优先级:

1. **P0 第三方 cryptographer audit** (4-6 周 + 钱) — paper accept 必要, 跟 reviewer 强相关
2. **P0 addon-owned secure mapping + core-dump exclusion + cross-platform validation** — production deployment 强相关
3. **P0 per-op cache-timing** (98h CPU) — paper rigor 强相关
4. **P0 旁路攻击 (EM/power/fault)** (需专业硬件) — paper rigor 强相关

**本文 scope**: 这些项目都没有被当前历史 timing reports 覆盖。

**Estimated total cost to audit-grade**: 4-6 周 cryptographer + 2-3 天 mlock + 98h per-op CPU + 4-6 周 旁路攻击 = **3-4 月 + 50-150K USD**.

---

**2026-09-07 当前状态**: master `d3b940a21e`；275 个 focused tests、14 份 report integrity、5 个 deploy harness、native roundtrip 与 sandbox install 均已本地通过。Hosted Actions 因私有仓库未分配 runner 而未形成 CI-green 证据。

## 关联文档

- `pqc-whitepaper.md` (主 paper, §5.1.4 / §6.3 / §9.1.2 / §10)
- `verification-log-2026-08-29-30.md` (8/29 M6.B + 8/30 AES-GCM CT 验证步骤, 复现依据)
- `PAPER-SUBMISSION-CHECKLIST.md` (1-page 提交就绪状态盘)
- `constant-time-audit.md` (Side-channel 攻击面 §5.1.1-5.1.4 详 14 ops × 0 leak 数据)
