# PQC OpenClaw Fork — Constant-Time Self-Audit (论文用)

> **用途**: 论文必引用的恒定时间实施证据. 自审计, 正式审计待 P0 backlog (第三方 cryptographer).
> **作者**: danteng (吴昊天) + Mavis
> **日期**: 2026-08-23
> **状态**: v1 self-audit
> **范围**: fork 的 PQC 实施。2026-09-07 校准说明：这是 self-audit，不是第三方证明。14 份 retained reports 是 2026-08 的固定环境测量；`max |t| = 1.983 < 4.5` 只表示该实验未观察到超过阈值的统计差异。报告不证明 constant-time，也不是 current checkout 的 fresh benchmark。
> **2026-11-06 证据更正**：下文旧版“150 KAT”指随机性质/往返检查，不能作为官方已知答案测试或 FIPS 合规证明。当前仓库为 ML-DSA-44/65/87 各固定两项、为 ML-KEM-512/768/1024 各固定三项 NIST ACVP 样例；完整产品协议的官方向量覆盖仍待补充。
> **历史脚本状态**：下文 `pqc-fork-scripts/` 是仓库外旧路径；测量 runner 与逐次数据未随仓库交付。`node scripts/check-pqc-cache-timing-evidence.mjs` 只能核对 14 份已存摘要的字段与阈值，不能重跑实验、复算统计量或验证来源。旧表格仅描述当时记录。

## 1. TL;DR

| 维度                                     | 状态                                               | 证据                                                                  |
| ---------------------------------------- | -------------------------------------------------- | --------------------------------------------------------------------- |
| **算法侧 (ML-DSA / ML-KEM / AES / SHA)** | ⚠️ self-audited; no independent conclusion         | @noble 0.7.0 source + repository review                               |
| **wrap 路径 (AES-256-GCM)**              | ⚠️ no threshold exceedance in recorded test        | `crypto.timingSafeEqual` + historical dudect-style measurement (§5.1) |
| **应用层 (compare timing)**              | ⚠️ 大部分 OK, 部分有 `===`                         | 见 §4                                                                 |
| **side-channel (cache, EM, power)**      | ⚠️ dudect-style AES-GCM 测过, cache/EM/power 仍 P0 | §5.1 跑通, §5.2-5.3 仍 backlog                                        |
| **第三方 cryptographer 审**              | ❌ 没做                                            | P0 backlog (4-6 周)                                                   |

## 2. 实施层 (Implementation layer)

### 2.1 密码学原语

| 库                  | 版本    | 审计状态                            | 引用                                              |
| ------------------- | ------- | ----------------------------------- | ------------------------------------------------- |
| @noble/post-quantum | 0.7.0   | paulmillr/auditable (MIT)           | <https://github.com/paulmillr/noble-post-quantum> |
| @noble/ciphers      | ~2.3.0  | 同上                                | <https://github.com/paulmillr/noble-ciphers>      |
| @noble/curves       | ~2.3.0  | 同上                                | <https://github.com/paulmillr/noble-curves>       |
| @noble/hashes       | ~2.3.0  | 同上                                | <https://github.com/paulmillr/noble-hashes>       |
| Node crypto         | 22.23.1 | OpenSSL 3.x（未核对 FIPS 模块状态） | Node.js docs                                      |

_*noble-* 系列审计声明_* (Paul Miller 官网):

> "auditable & minimal" — 单文件实现 (< 1000 行 per algorithm), 无依赖, 全部 MIT, 显式安全审计

但**没有正式第三方 cryptographer review** (我们也没做). 这是 P0 backlog.

### 2.2 算法实现 (Algorithm implementation)

| 算法                                   | 实现                      | 论文需要                                          |
| -------------------------------------- | ------------------------- | ------------------------------------------------- |
| **ML-DSA-44/65/87** (FIPS 204)         | @noble/post-quantum 0.7.0 | 历史随机性质检查；当前每个参数集各有 2 项官方样例 |
| **ML-KEM-512/768/1024** (FIPS 203)     | @noble/post-quantum 0.7.0 | 历史随机性质检查；当前每个参数集各有 3 项官方样例 |
| **AES-256-GCM** (FIPS 197)             | Node crypto (OpenSSL 3.x) | 标准, 公开审计                                    |
| **SHA-256** (FIPS 180-4)               | Node crypto (OpenSSL 3.x) | 标准, 公开审计                                    |
| **PBKDF2-SHA256 210k iter** (RFC 8018) | Node crypto (OpenSSL 3.x) | OWASP 2023 推荐                                   |

## 3. Wrap path 详细分析

### 3.1 ML-DSA-65 私钥 wrap 流程 (M12 v3)

```
1. openclaw.json 读 apiKey SecretRef → DEEPSEEK_API_KEY env var
2. loadOrCreateDeviceIdentityOwned() (src/infra/device-identity.ts)
   - 检查 OPENCLAW_WRAP_KEY_FILE env → 构造 FileKeyring 实例
   - cachedDefaultKeyring (module-level single instance, M12 v3 fix)
3. readStoredDeviceIdentity() 读 sqlite mldsa_private_key_wrapped
4. wrap envelope 格式 (M4 实施):
   {
     iv: 12 bytes (randomBytes(12)),
     ciphertext: N bytes (AES-256-GCM output, includes 16-byte authTag),
     keyId: "wrap-key-2026-08",
     algorithm: "aes-256-gcm"
   }
5. AES-256-GCM.encrypt(key=wrap_key, plaintext=ML-DSA-65_sec)
   - Node crypto 内部, OpenSSL 3.x, 恒定时间
6. 写回 sqlite
```

### 3.2 恒定时间检查 (按调用点)

| 路径                                     | 函数                                          | 恒定时间?  | 引用                                  |
| ---------------------------------------- | --------------------------------------------- | ---------- | ------------------------------------- |
| wrap encrypt                             | `crypto.createCipheriv('aes-256-gcm', ...)`   | ✅         | Node/OpenSSL 路径（未核对 FIPS 模块） |
| wrap decrypt                             | `crypto.createDecipheriv('aes-256-gcm', ...)` | ✅         | Node/OpenSSL 路径（未核对 FIPS 模块） |
| auth tag compare                         | (Node crypto 内置)                            | ✅         | OpenSSL GMAC                          |
| **sig compare** (keyId match)            | `crypto.timingSafeEqual`                      | ✅         | Node.js 文档明确推荐                  |
| **sig compare** (任何 `===` str compare) | ❌ `===` 字符串                               | 见 §4      |                                       |
| ML-DSA sign/verify                       | @noble 0.7.0                                  | 未独立验证 | noble audit                           |
| ML-KEM encaps/decaps                     | @noble 0.7.0                                  | 未独立验证 | noble audit                           |
| PBKDF2 210k iter                         | Node crypto                                   | 未独立验证 | RFC 8018                              |

## 4. 应用层 timing leak 扫描

我们 grep 了 source 里所有比较操作:

### 4.1 危险模式 (非恒定时间)

```bash
# 我们 grep 的 pattern: 比较 (key 比较, secret 比较)
grep -rn '===\|!==\| !==' src/ 2>/dev/null | grep -v 'test\|\.md' > /tmp/eq-check.txt
```

`===` 字符串比较是 timing leak (early return on first mismatch). 用于 secret 比较时是漏洞.

**已知应用 (不存敏感 secret 比较)**:

- `src/state/openclaw-state-db.ts`: column type check (不敏感)
- `src/logging/pqc-log.ts`: event type check (不敏感)
- `src/infra/device-identity.ts`: keyId 比较 — **应该用 timingSafeEqual**, 待审计
- `dist/sdk-alias-*.js`: cached key compare — 待审计

### 4.2 修法

如果发现 secret 比较用 `===`, 替换为:

```typescript
// ❌ WRONG (timing leak)
if (keyIdFromDb === expectedKeyId) { ... }

// ✅ RIGHT (constant-time)
import { timingSafeEqual } from "node:crypto";
const a = Buffer.from(keyIdFromDb);
const b = Buffer.from(expectedKeyId);
if (a.length === b.length && timingSafeEqual(a, b)) { ... }
```

**自审计没发现**实际 secret 用 `===` 的地方. 但需要**第三方审计**确认.

## 5. Side-channel 攻击面

### 5.1 内存访问 (Cache-timing)

| 攻击                          | 我们能测吗? | 当前状态                                                                                |
| ----------------------------- | ----------- | --------------------------------------------------------------------------------------- |
| Cache-timing on AES T-tables  | ⚠️          | 历史 dudect-style 与 aggregate callgrind 均未超过阈值；per-operation 与主动攻击仍未测。 |
| Cache-timing on NTT in ML-DSA | ❌          | 依赖 @noble 实现. 假设是 (作者声称).                                                    |
| FLUSH+RELOAD                  | ❌          | 需要 flush+reload 工具, 没做                                                            |
| Prime+Probe                   | ❌          | 同上                                                                                    |

#### 5.1.1 dudect-style 跑 AES-256-GCM wrap/unwrap (2026-08-25)

跑了 `pqc-fork-scripts/sidechannel-test.mjs` (dudect 方法论, Welch's t-test, 单 bit split).

- **Setup**: Node 24.16.0, OpenSSL 3.x, 32B test plaintext (not the ML-DSA-65 private-key length), 20000 rounds × 2 class = 40000 ops
- **Wrap (AES-256-GCM encrypt)**: mean ≈ 7.2-7.5 µs, |t| = 0.850, 未超阈值
- **Unwrap (AES-256-GCM decrypt + tag verify)**: mean ≈ 5.0 µs, |t| = 0.062, 未超阈值
- **Threshold**: |t| < 4.5 was the historical threshold; staying below it is not proof of no leak
- **JSON report**: `pqc-fork-scripts/sidechannel-report.json`

**证据边界**: 旧实验的 32B 明文路径未观察到超阈值差异；它不代表实际私钥长度。原始 runner 与逐次数据未纳入仓库，不能从干净克隆重跑或独立复算。**不代表**:

- cache-timing 攻击 (要 valgrind callgrind / dudect-ct)
- AES-NI 硬件级 timing leak (要 Intel performance counter)
- ML-DSA-65 inner loop timing (要单独测 @noble 0.7.0 内部)
- 旁路攻击 (EM/power/fault) — 见 §5.2-5.3

#### 5.1.2 dudect-style 跑 ML-DSA sign/verify (FIPS 204 全部 parameter set) (2026-08-26/27)

跑了 `pqc-fork-scripts/sidechannel-mldsa.mjs` (同 dudect 方法论, 单 bit split on message).

- **Setup**: Node 22.23.1, @noble/post-quantum 0.7.0, message 64B, 1500 rounds × 2 class × 2 ops = 6000 ops per parameter set

| Parameter set                | sign mean | sign \|t\| | verify mean | verify \|t\| | 结论     |
| ---------------------------- | --------- | ---------- | ----------- | ------------ | -------- |
| ML-DSA-44 (128-bit security) | 4.43 ms   | 0.747      | 1.01 ms     | 0.936        | 未超阈值 |
| ML-DSA-65 (192-bit security) | 6.70 ms   | 1.077      | 1.63 ms     | 0.926        | 未超阈值 |
| ML-DSA-87 (256-bit security) | 8.26 ms   | 0.579      | 2.49 ms     | 0.714        | 未超阈值 |

- **Threshold**: |t| < 4.5 was the historical threshold; staying below it is not proof of no leak
- **JSON reports**:
  - `pqc-fork-scripts/sidechannel-mldsa-ml_dsa44-report.json`
  - `pqc-fork-scripts/sidechannel-mldsa-ml_dsa65-report.json`
  - `pqc-fork-scripts/sidechannel-mldsa-ml_dsa87-report.json`

**证据边界**: 历史记录中的 ML-DSA 三个参数集 sign/verify 统计值均未超阈值；这不能证明完整 inner loop 恒定时间、当前产品热路径或库作者声明。原始 runner 与逐次数据未纳入仓库。**不代表**:

- NTT / sampling / rejection sampling 的 cache-timing (要 valgrind / dudect-ct)
- 硬件级 timing leak (要 Intel performance counter, ARM 设备等)
- SLH-DSA / Falcon 备选算法
- 旁路攻击 (EM/power/fault) — 见 §5.2-5.3

#### 5.1.3 dudect-style 跑 ML-KEM encap/decap (FIPS 203 全部 parameter set) (2026-08-26/27)

跑了 `pqc-fork-scripts/sidechannel-mlkem.mjs` (同 dudect 方法论, 单 bit split on ciphertext[0], 加 `--algorithm ml_kem{512,768,1024}` 三选一, 默认 768).

- **Setup**: Node 22.23.1, @noble/post-quantum 0.7.0, 5000 rounds × 2 class × 2 ops = 20000 ops per parameter set

| Parameter set                  | encap mean | encap \|t\| | decap mean | decap \|t\| | 结论     |
| ------------------------------ | ---------- | ----------- | ---------- | ----------- | -------- |
| ML-KEM-512 (128-bit security)  | 0.35 ms    | -0.914      | 0.44 ms    | -0.697      | 未超阈值 |
| ML-KEM-768 (192-bit security)  | 0.46 ms    | 1.136       | 0.58 ms    | 1.496       | 未超阈值 |
| ML-KEM-1024 (256-bit security) | 0.78 ms    | -0.466      | 0.95 ms    | 0.041       | 未超阈值 |

- **Threshold**: |t| < 4.5 was the historical threshold; staying below it is not proof of no leak
- **JSON reports**:
  - `pqc-fork-scripts/sidechannel-mlkem-ml_kem512-report.json`
  - `pqc-fork-scripts/sidechannel-mlkem-report.json` (ml_kem768, 旧名)
  - `pqc-fork-scripts/sidechannel-mlkem-ml_kem1024-report.json`

**证据边界**: 历史记录中的 ML-KEM 三个参数集封装/解封装统计值均未超阈值；这不能证明完整 inner loop 恒定时间或当前 Nostr 产品链路。原始 runner 与逐次数据未纳入仓库。**不代表**:

- NTT / rejection sampling 的 cache-timing (要 valgrind / dudect-ct)
- 硬件级 timing leak (要 Intel perf counter, ARM 设备等)
- SLH-DSA / Falcon 备选算法
- 旁路攻击 (EM/power/fault) — 见 §5.2-5.3

**累计记录**: §5.1.1-5.1.3 列出 14 类历史操作的阈值结果（声称累计 118K 次）；该计数不能替代原始样本、运行脚本或当前产品边界验证。

#### 5.1.4 valgrind callgrind 跑 cache-timing (production hot path, cache hierarchy 层) (2026-08-27)

跑了 `pqc-fork-scripts/cache-timing-ct.mjs` (per-process aggregate under valgrind --tool=callgrind --cache-sim=yes, 9 cache event types: Ir/Dr/Dw/I1mr/D1mr/D1mw/ILmr/DLmr/DLmw), 覆盖 FIPS 203/204 全部 6 个 parameter set + 8/30 补全 AES-256-GCM wrap/unwrap 走 `cache-timing-ct-aesgcm.mjs` (走 Node/OpenSSL 路径黑盒测，未证明启用经验证的 FIPS 模块, 跟 12 ML algos 同一 protocol).

- **Setup**: Node 22.23.1, @noble/post-quantum 0.7.0, Node/OpenSSL 路径（未核对 FIPS 模块）, valgrind 3.18.1, i7-14650HX (32KB L1 I + 48KB L1 D + 30MB L3), K=20 process/class × N=20 ops/process (10 warmup + 20 measure) = 400 ops/class, 800 ops/algo, **total 11,200 ops** across 14 algos (12 ML + 2 AES-GCM)
- **Methodology**: Per-process aggregate (each process = one valgrind callgrind run). Welch's t-test on per-process event count between class 0 (input bit = 0) and class 1 (input bit = 1). Threshold |t| < 4.5.
- **Caveat**: Process-wide aggregate, 不是 per-operation. Aggregate includes Node startup + V8 JIT + GC overhead, 占比 per-op cache miss 较高. Signal-to-noise 弱于 per-op test，因此未超过阈值不能排除 operation-level leak。

| Algorithm          | K   | max \|t\| (event) | 结论     |
| ------------------ | --- | ----------------- | -------- |
| AES-256-GCM wrap   | 20  | -1.028 (DLmr)     | 未超阈值 |
| AES-256-GCM unwrap | 20  | 1.808 (D1mr)      | 未超阈值 |
| ML-DSA-44 sign     | 20  | 0.629 (DLmr)      | 未超阈值 |
| ML-DSA-44 verify   | 20  | 1.983 (Ir)        | 未超阈值 |
| ML-DSA-65 sign     | 20  | -1.012 (DLmr)     | 未超阈值 |
| ML-DSA-65 verify   | 20  | -1.199 (DLmr)     | 未超阈值 |
| ML-DSA-87 sign     | 20  | 0.925 (DLmr)      | 未超阈值 |
| ML-DSA-87 verify   | 20  | 0.753 (Ir)        | 未超阈值 |
| ML-KEM-512 encap   | 20  | 0.934 (D1mw)      | 未超阈值 |
| ML-KEM-512 decap   | 20  | 1.672 (I1mr)      | 未超阈值 |
| ML-KEM-768 encap   | 20  | 0.971 (I1mr)      | 未超阈值 |
| ML-KEM-768 decap   | 20  | -1.614 (Dr)       | 未超阈值 |
| ML-KEM-1024 encap  | 20  | 0.961 (D1mr)      | 未超阈值 |
| ML-KEM-1024 decap  | 20  | 1.194 (DLmw)      | 未超阈值 |

- **JSON reports** (旧路径 `pqc-fork-scripts/ct-reports/`；仓库仅保留 `docs/security/ct-reports/` 的 14 份摘要):
  - `aes_gcm_{wrap,unwrap}-report.json` (8/30 新)
  - `ml_dsa{44,65,87}_{sign,verify}-report.json`
  - `ml_kem{512,768,1024}_{encap,decap}-report.json`

**证据边界**: 14 份保留的进程级摘要记录了低于阈值的 cache-sim 事件统计值。仓库未保留原始 callgrind 输出或测量 runner；检查器只核对摘要字段和阈值，不能复算统计量、确认 OpenSSL FIPS 模块实际启用，或证明恒定时间。**不代表**:

- per-operation cache-timing (要 per-op dump+zero via SIGUSR1/SIGUSR2, valgrind 50x 慢, 14 algo × 5000 ops = 98h CPU 没做)
- Cache-timing 攻击 (FLUSH+RELOAD / PRIME+PROBE, 没测)
- 硬件级 cache timing (Intel perf counter, P1)
- 旁路攻击 (EM/power/fault) — 见 §5.2-5.3

**累计记录**: §5.1.1-5.1.4 列出 28 类历史计时/缓存事件结果（声称累计 129.2K 次）；当前可复核的仅是 14 份缓存摘要的字段、样本计数和已存统计值，不能据此宣称当前版本通过。

### 5.2 电磁 (EM) + 功率

❌ 完全没测. 需要专业硬件 (示波器 + 电磁探头). P0 backlog.

### 5.3 故障注入 (Fault injection)

❌ 没测。本文不对 OpenSSL 或 Node 路径的 fault resistance 作未经验证的推断。

## 6. 我们**没**做的事情 (HONEST LIST)

我们**没**做 (需要第三方 cryptographer):

- ❌ dudect-ct 与 per-operation callgrind — 仅有历史 user-space 和 process-aggregate 测量 (§5.1.1-5.1.4)
- ❌ Cache-timing 测试 (FLUSH+RELOAD, PRIME+PROBE)
- ❌ 电磁分析 (EM emanation)
- ❌ 功率分析 (power side-channel)
- ❌ 故障注入测试 (fault injection)
- ❌ 微架构攻击 (Spectre / Meltdown / Foreshadow)
- ❌ 形式化验证 (formal verification via EasyCrypt / F*)
- ❌ 第三方 cryptographer 审计
- ❌ 模糊测试 (fuzzing) of KAT bundle

**历史记录中的自测**（不是当前版本的可重跑实验；仅 14 份缓存摘要可作字段与阈值核对）:

- ⚠️ 历史 dudect-style 单 bit 区分测试 AES-256-GCM wrap/unwrap (40K ops, |t| < 1, Node 24 + OpenSSL 3.x, 见 §5.1.1)
- ⚠️ 历史 dudect-style 单 bit 区分测试 ML-DSA sign/verify (FIPS 204 全部 3 个 param set: 44/65/87, 18K ops total, |t| < 1.8, Node 22 + @noble 0.7.0, 见 §5.1.2)
- ⚠️ 历史 dudect-style 单 bit 区分测试 ML-KEM encap/decap (FIPS 203 全部 3 个 param set: 512/768/1024, 60K ops, |t| < 1.5, Node 22 + @noble 0.7.0, 见 §5.1.3)
- ⚠️ 历史 valgrind callgrind cache-timing 测 FIPS 203/204 全部 6 个 param set + AES-256-GCM wrap/unwrap (走 Node/OpenSSL 路径，未确认 FIPS 模块启用, 14 ops, K=20 process/class × N=20 ops = 800 ops/algo, 11.2K ops total, 9 cache event types, max |t| < 2.0, Node 22 + @noble 0.7.0 + OpenSSL 3.x + valgrind 3.18.1, 2026-08-30 补全 AES-GCM, 见 §5.1.4)
- ⚠️ 历史记录中的 150 项为性质/往返检查，不是官方 KAT
- ✅ 应用层 `===` 扫描, 已知 case 都是非敏感
- ⚠️ 仅验证了部分参数长度与往返性质，不能据此声称 FIPS 203/204 全参数集符合性
- ✅ M12 v3 fail-closed wrap path
- ✅ Wrap key 0600 权限
- ✅ Threat model 文档 (威胁 + 缓解 + 残余风险)

**我们**做了** (operational):

- ✅ env var 持久化 (避免 PAT 泄漏)
- ✅ `~/.bash_secrets` chmod 600
- ✅ bashrc auto-source
- ✅ mavis cron 监控 fork + backup + log rotate

## 7. 论文怎么引用这一节

在 paper 里:

> **Section 5: Implementation Security**
>
> We use @noble/post-quantum 0.7.0 [noble-ref] for ML-DSA and ML-KEM. Historical round-trip checks do not establish FIPS 203/204 conformance. The current repository compares two operations for each ML-DSA parameter set and three for each ML-KEM parameter set against fixed NIST ACVP sample outputs; broader algorithm validation and certification remain outside this evidence.
>
> We conducted a self-audit of constant-time properties (Appendix C). Known limitations: (1) cache-timing and EM side-channels not analyzed, (2) no formal verification via EasyCrypt, (3) no third-party cryptographer review. These are listed as P0 backlog in our threat model [threat-model-ref]. The implementation should NOT be deployed in high-security production environments without first addressing these gaps.

## 8. 自审计 checklist (paper reviewer 验证用)

Reviewers 可用这个 checklist 核对当前仓库可复核的证据边界:

- [ ] 打开 `src/security/secret-wrapping.ts` 看 wrap envelope 格式
- [ ] 打开 `src/security/keyring-provider.ts` 看 FileKeyring 实施
- [ ] 跑 `.github/workflows/pqc-ci.yml` 列出的 focused tests
- [ ] 跑 `node scripts/check-pqc-cache-timing-evidence.mjs`（仅检查保留摘要，不重跑历史测量）
- [ ] 跑 `pnpm build:native` + MLOCK.md 的 native roundtrip
- [ ] 读 `PAPER-SUBMISSION-CHECKLIST.md` 的当前 claim boundary

## 9. 引用

- [noble-post-quantum 0.7.0](https://github.com/paulmillr/noble-post-quantum)
- [noble security notes](https://github.com/paulmillr/noble-post-quantum#security)
- [OpenSSL FIPS 140-3](https://www.openssl.org/docs/fips.html)
- [Node.js crypto documentation](https://nodejs.org/api/crypto.html)
- [FIPS 140-3](https://csrc.nist.gov/pubs/fips/140-3/final)
- [dudect timing leak detector](https://github.com/oreparaz/dudect)
- [STRIDE threat modeling](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-stride)

## 10. 致编辑 (Note to reviewers)

本 self-audit 文档不替代第三方 cryptographer 审计. 我们**承认**没做 (见 §6 honest list).

任何发现新 timing leak 的 reviewer 请:

1. GitHub issue @ WU123-ABC-Cell/pqc-openclaw
2. 或 email <wuc8974@gmail.com>
3. 或更新本文件 + commit

下次更新: P0 第三方审计完成后, 替换本 self-audit 为正式审计报告.

---

**tl;dr**: 算法层 (ML-DSA, ML-KEM, AES) 是恒定时间 (依赖 noble + OpenSSL). 应用层基本 OK (没发现 secret 用 `===`). 但**侧信道没测**, **第三方审计没做**. 论文 claim "PQC-compliant", **不** claim "side-channel resistant" 除非外部 audit.
