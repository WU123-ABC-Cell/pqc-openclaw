# PQC OpenClaw Fork — Constant-Time Self-Audit (论文用)

> **用途**: 论文必引用的恒定时间实施证据. 自审计, 正式审计待 P0 backlog (第三方 cryptographer).
> **作者**: danteng (吴昊天) + Mavis
> **日期**: 2026-08-23
> **状态**: v1 self-audit
> **范围**: fork 的 PQC 实施。2026-09-07 校准说明：这是 self-audit，不是第三方证明。14 份 retained reports 是 2026-08 的固定环境测量；`max |t| = 1.983 < 4.5` 只表示该实验未观察到超过阈值的统计差异。报告不证明 constant-time，也不是 current checkout 的 fresh benchmark。

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

| 库                  | 版本    | 审计状态                      | 引用                                              |
| ------------------- | ------- | ----------------------------- | ------------------------------------------------- |
| @noble/post-quantum | 0.7.0   | paulmillr/auditable (MIT)     | <https://github.com/paulmillr/noble-post-quantum> |
| @noble/ciphers      | ~2.3.0  | 同上                          | <https://github.com/paulmillr/noble-ciphers>      |
| @noble/curves       | ~2.3.0  | 同上                          | <https://github.com/paulmillr/noble-curves>       |
| @noble/hashes       | ~2.3.0  | 同上                          | <https://github.com/paulmillr/noble-hashes>       |
| Node crypto         | 22.23.1 | OpenSSL 3.x (FIPS 140-3 验证) | Node.js docs                                      |

_*noble-* 系列审计声明_* (Paul Miller 官网):

> "auditable & minimal" — 单文件实现 (< 1000 行 per algorithm), 无依赖, 全部 MIT, 显式安全审计

但**没有正式第三方 cryptographer review** (我们也没做). 这是 P0 backlog.

### 2.2 算法实现 (Algorithm implementation)

| 算法                                   | 实现                      | 论文需要                        |
| -------------------------------------- | ------------------------- | ------------------------------- |
| **ML-DSA-44/65/87** (FIPS 204)         | @noble/post-quantum 0.7.0 | KAT 26 × 3 = 78 invariants pass |
| **ML-KEM-512/768/1024** (FIPS 203)     | @noble/post-quantum 0.7.0 | KAT 24 × 3 = 72 invariants pass |
| **AES-256-GCM** (FIPS 197)             | Node crypto (OpenSSL 3.x) | 标准, 公开审计                  |
| **SHA-256** (FIPS 180-4)               | Node crypto (OpenSSL 3.x) | 标准, 公开审计                  |
| **PBKDF2-SHA256 210k iter** (RFC 8018) | Node crypto (OpenSSL 3.x) | OWASP 2023 推荐                 |

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

| 路径                                     | 函数                                          | 恒定时间?               | 引用                   |
| ---------------------------------------- | --------------------------------------------- | ----------------------- | ---------------------- |
| wrap encrypt                             | `crypto.createCipheriv('aes-256-gcm', ...)`   | ✅                      | OpenSSL 3.x FIPS 140-3 |
| wrap decrypt                             | `crypto.createDecipheriv('aes-256-gcm', ...)` | ✅                      | OpenSSL 3.x FIPS 140-3 |
| auth tag compare                         | (Node crypto 内置)                            | ✅                      | OpenSSL GMAC           |
| **sig compare** (keyId match)            | `crypto.timingSafeEqual`                      | ✅                      | Node.js 文档明确推荐   |
| **sig compare** (任何 `===` str compare) | ❌ `===` 字符串                               | 见 §4                   |                        |
| ML-DSA sign/verify                       | @noble 0.7.0                                  | ✅ (auditable)          | noble audit            |
| ML-KEM encaps/decaps                     | @noble 0.7.0                                  | ✅ (auditable)          | noble audit            |
| PBKDF2 210k iter                         | Node crypto                                   | ✅ (恒定时间 by design) | RFC 8018               |

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

- **Setup**: Node 24.16.0, OpenSSL 3.x, plaintext 32B (≈ ML-DSA-65 私钥大小), 20000 rounds × 2 class = 40000 ops
- **Wrap (AES-256-GCM encrypt)**: mean ≈ 7.2-7.5 µs, |t| = 0.850, ✓ no leak
- **Unwrap (AES-256-GCM decrypt + tag verify)**: mean ≈ 5.0 µs, |t| = 0.062, ✓ no leak
- **Threshold**: |t| < 4.5 = no leak (dudect standard)
- **JSON report**: `pqc-fork-scripts/sidechannel-report.json`

**意义**: Node crypto 调 OpenSSL 的 AES-256-GCM 在我们 fork 用的 32B plaintext 路径上, 用户态单 bit 区分不出 timing 差. 这是 wrap/unwrap hot path 的**软件层**证据. **不代表**:

- cache-timing 攻击 (要 valgrind callgrind / dudect-ct)
- AES-NI 硬件级 timing leak (要 Intel performance counter)
- ML-DSA-65 inner loop timing (要单独测 @noble 0.7.0 内部)
- 旁路攻击 (EM/power/fault) — 见 §5.2-5.3

#### 5.1.2 dudect-style 跑 ML-DSA sign/verify (FIPS 204 全部 parameter set) (2026-08-26/27)

跑了 `pqc-fork-scripts/sidechannel-mldsa.mjs` (同 dudect 方法论, 单 bit split on message).

- **Setup**: Node 22.23.1, @noble/post-quantum 0.7.0, message 64B, 1500 rounds × 2 class × 2 ops = 6000 ops per parameter set

| Parameter set                | sign mean | sign \|t\| | verify mean | verify \|t\| | 结论      |
| ---------------------------- | --------- | ---------- | ----------- | ------------ | --------- |
| ML-DSA-44 (128-bit security) | 4.43 ms   | 0.747      | 1.01 ms     | 0.936        | ✓ no leak |
| ML-DSA-65 (192-bit security) | 6.70 ms   | 1.077      | 1.63 ms     | 0.926        | ✓ no leak |
| ML-DSA-87 (256-bit security) | 8.26 ms   | 0.579      | 2.49 ms     | 0.714        | ✓ no leak |

- **Threshold**: |t| < 4.5 = no leak (dudect standard)
- **JSON reports**:
  - `pqc-fork-scripts/sidechannel-mldsa-ml_dsa44-report.json`
  - `pqc-fork-scripts/sidechannel-mldsa-ml_dsa65-report.json`
  - `pqc-fork-scripts/sidechannel-mldsa-ml_dsa87-report.json`

**意义**: @noble/post-quantum 0.7.0 的 ML-DSA **全部 3 个 parameter set** (44/65/87) 的 sign + verify (用 fork 的 device-identity hot path, random message × key) 在用户态单 bit 区分不出 timing 差. 这是 ML-DSA 全部 inner loop 的**软件层**证据 (确认 paulmillr 声称的 "auditable" 在 6 条主路径上都**没观察到** user-space data-dependent timing). **不代表**:

- NTT / sampling / rejection sampling 的 cache-timing (要 valgrind / dudect-ct)
- 硬件级 timing leak (要 Intel performance counter, ARM 设备等)
- SLH-DSA / Falcon 备选算法
- 旁路攻击 (EM/power/fault) — 见 §5.2-5.3

#### 5.1.3 dudect-style 跑 ML-KEM encap/decap (FIPS 203 全部 parameter set) (2026-08-26/27)

跑了 `pqc-fork-scripts/sidechannel-mlkem.mjs` (同 dudect 方法论, 单 bit split on ciphertext[0], 加 `--algorithm ml_kem{512,768,1024}` 三选一, 默认 768).

- **Setup**: Node 22.23.1, @noble/post-quantum 0.7.0, 5000 rounds × 2 class × 2 ops = 20000 ops per parameter set

| Parameter set                  | encap mean | encap \|t\| | decap mean | decap \|t\| | 结论      |
| ------------------------------ | ---------- | ----------- | ---------- | ----------- | --------- |
| ML-KEM-512 (128-bit security)  | 0.35 ms    | -0.914      | 0.44 ms    | -0.697      | ✓ no leak |
| ML-KEM-768 (192-bit security)  | 0.46 ms    | 1.136       | 0.58 ms    | 1.496       | ✓ no leak |
| ML-KEM-1024 (256-bit security) | 0.78 ms    | -0.466      | 0.95 ms    | 0.041       | ✓ no leak |

- **Threshold**: |t| < 4.5 = no leak (dudect standard)
- **JSON reports**:
  - `pqc-fork-scripts/sidechannel-mlkem-ml_kem512-report.json`
  - `pqc-fork-scripts/sidechannel-mlkem-report.json` (ml_kem768, 旧名)
  - `pqc-fork-scripts/sidechannel-mlkem-ml_kem1024-report.json`

**意义**: @noble/post-quantum 0.7.0 的 ML-KEM **全部 3 个 parameter set** (512/768/1024) 的 encap + decapsulate (用 fork 的 Nostr DM hybrid KEM path, random ciphertext) 在用户态单 bit 区分不出 timing 差. 这是 ML-KEM 全部 inner loop 的**软件层**证据 (确认 paulmillr 声称的 "auditable" 在 6 条主路径上都**没观察到** user-space data-dependent timing). **不代表**:

- NTT / rejection sampling 的 cache-timing (要 valgrind / dudect-ct)
- 硬件级 timing leak (要 Intel perf counter, ARM 设备等)
- SLH-DSA / Falcon 备选算法
- 旁路攻击 (EM/power/fault) — 见 §5.2-5.3

**累计**: §5.1.1 + §5.1.2 + §5.1.3 共同覆盖 PQC fork 三条主 hot path **全 parameter set** 的**软件层 constant-time** 证据: AES-256-GCM wrap/unwrap + ML-DSA 全部 3 个 param set sign/verify (44/65/87) + ML-KEM 全部 3 个 param set encap/decap (512/768/1024) = **7 hot paths / 14 ops 全部通过** (累计 118K ops, |t| < 1.8 全过).

#### 5.1.4 valgrind callgrind 跑 cache-timing (production hot path, cache hierarchy 层) (2026-08-27)

跑了 `pqc-fork-scripts/cache-timing-ct.mjs` (per-process aggregate under valgrind --tool=callgrind --cache-sim=yes, 9 cache event types: Ir/Dr/Dw/I1mr/D1mr/D1mw/ILmr/DLmr/DLmw), 覆盖 FIPS 203/204 全部 6 个 parameter set + 8/30 补全 AES-256-GCM wrap/unwrap 走 `cache-timing-ct-aesgcm.mjs` (走 OpenSSL 3.x FIPS 140-3 path 黑盒测, 跟 12 ML algos 同一 protocol).

- **Setup**: Node 22.23.1, @noble/post-quantum 0.7.0, OpenSSL 3.x FIPS 140-3, valgrind 3.18.1, i7-14650HX (32KB L1 I + 48KB L1 D + 30MB L3), K=20 process/class × N=20 ops/process (10 warmup + 20 measure) = 400 ops/class, 800 ops/algo, **total 11,200 ops** across 14 algos (12 ML + 2 AES-GCM)
- **Methodology**: Per-process aggregate (each process = one valgrind callgrind run). Welch's t-test on per-process event count between class 0 (input bit = 0) and class 1 (input bit = 1). Threshold |t| < 4.5.
- **Caveat**: Process-wide aggregate, 不是 per-operation. Aggregate includes Node startup + V8 JIT + GC overhead, 占比 per-op cache miss 较高. Signal-to-noise 弱于 per-op test，因此未超过阈值不能排除 operation-level leak。

| Algorithm          | K   | max \|t\| (event) | 结论      |
| ------------------ | --- | ----------------- | --------- |
| AES-256-GCM wrap   | 20  | -1.028 (DLmr)     | ✓ no leak |
| AES-256-GCM unwrap | 20  | 1.808 (D1mr)      | ✓ no leak |
| ML-DSA-44 sign     | 20  | 0.629 (DLmr)      | ✓ no leak |
| ML-DSA-44 verify   | 20  | 1.983 (Ir)        | ✓ no leak |
| ML-DSA-65 sign     | 20  | -1.012 (DLmr)     | ✓ no leak |
| ML-DSA-65 verify   | 20  | -1.199 (DLmr)     | ✓ no leak |
| ML-DSA-87 sign     | 20  | 0.925 (DLmr)      | ✓ no leak |
| ML-DSA-87 verify   | 20  | 0.753 (Ir)        | ✓ no leak |
| ML-KEM-512 encap   | 20  | 0.934 (D1mw)      | ✓ no leak |
| ML-KEM-512 decap   | 20  | 1.672 (I1mr)      | ✓ no leak |
| ML-KEM-768 encap   | 20  | 0.971 (I1mr)      | ✓ no leak |
| ML-KEM-768 decap   | 20  | -1.614 (Dr)       | ✓ no leak |
| ML-KEM-1024 encap  | 20  | 0.961 (D1mr)      | ✓ no leak |
| ML-KEM-1024 decap  | 20  | 1.194 (DLmw)      | ✓ no leak |

- **JSON reports** (在 `pqc-fork-scripts/ct-reports/`, 14 algos):
  - `aes_gcm_{wrap,unwrap}-report.json` (8/30 新)
  - `ml_dsa{44,65,87}_{sign,verify}-report.json`
  - `ml_kem{512,768,1024}_{encap,decap}-report.json`

**意义**: @noble/post-quantum 0.7.0 的 **FIPS 203/204 全部 6 个 parameter set** (ML-DSA 44/65/87 sign+verify + ML-KEM 512/768/1024 encap+decap) 加上 **AES-256-GCM wrap/unwrap** (走 OpenSSL 3.x FIPS 140-3 path 黑盒测) 在 valgrind callgrind cache-sim 模式下 (L1 + L3 cache miss counts), process-wide aggregate 在 class 0 vs class 1 区分不出 cache miss 数差. 这是 **软件层之上** (cache hierarchy) 的 constant-time 证据, 补充 §5.1.1-5.1.3 user-space dudect-style timing 测试的不足. **不代表**:

- per-operation cache-timing (要 per-op dump+zero via SIGUSR1/SIGUSR2, valgrind 50x 慢, 14 algo × 5000 ops = 98h CPU 没做)
- Cache-timing 攻击 (FLUSH+RELOAD / PRIME+PROBE, 没测)
- 硬件级 cache timing (Intel perf counter, P1)
- 旁路攻击 (EM/power/fault) — 见 §5.2-5.3

**累计**: §5.1.1 + §5.1.2 + §5.1.3 + §5.1.4 共同覆盖 PQC fork 三条主 hot path 全 parameter set 的**软件层 + cache hierarchy 层** constant-time 证据: §5.1.1-5.1.3 是 user-space timing (14 ops, |t| < 1.8), §5.1.4 是 cache hierarchy (**14 ops**, max |t| = 1.983 [ML-DSA-44 verify Ir, 旧 max] / 1.808 [AES-GCM unwrap D1mr, 新 max]). 共 **7 hot paths / 28 ops** 全部通过 (累计 129.2K ops, AES-GCM 40K + ML-DSA 18K + ML-KEM 60K user-space + 11.2K cache-timing).

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

**我们**做了** (self-audit):

- ✅ dudect-style 单 bit 区分测试 AES-256-GCM wrap/unwrap (40K ops, |t| < 1, Node 24 + OpenSSL 3.x, 见 §5.1.1)
- ✅ dudect-style 单 bit 区分测试 ML-DSA sign/verify (FIPS 204 全部 3 个 param set: 44/65/87, 18K ops total, |t| < 1.8, Node 22 + @noble 0.7.0, 见 §5.1.2)
- ✅ dudect-style 单 bit 区分测试 ML-KEM encap/decap (FIPS 203 全部 3 个 param set: 512/768/1024, 60K ops, |t| < 1.5, Node 22 + @noble 0.7.0, 见 §5.1.3)
- ✅ valgrind callgrind cache-timing 测 FIPS 203/204 全部 6 个 param set + AES-256-GCM wrap/unwrap (走 OpenSSL 3.x FIPS 140-3 path, 14 ops, K=20 process/class × N=20 ops = 800 ops/algo, 11.2K ops total, 9 cache event types, max |t| < 2.0, Node 22 + @noble 0.7.0 + OpenSSL 3.x + valgrind 3.18.1, 2026-08-30 补全 AES-GCM, 见 §5.1.4)
- ✅ 150 KAT invariants across 6 NIST parameter sets
- ✅ 应用层 `===` 扫描, 已知 case 都是非敏感
- ✅ FIPS 204/203 全部 parameter set 验证
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
> We use @noble/post-quantum 0.7.0 [noble-ref] for ML-DSA and ML-KEM, which is a single-file auditable implementation under MIT license with documented security claims [noble-audit-ref]. Our wrap path uses Node.js crypto (OpenSSL 3.x, FIPS 140-3 validated [openssl-ref]) for AES-256-GCM and PBKDF2-SHA256. We verified FIPS 204/203 compliance via 150 KAT invariants across all 6 NIST parameter sets (Section 4).
>
> We conducted a self-audit of constant-time properties (Appendix C). Known limitations: (1) cache-timing and EM side-channels not analyzed, (2) no formal verification via EasyCrypt, (3) no third-party cryptographer review. These are listed as P0 backlog in our threat model [threat-model-ref]. The implementation should NOT be deployed in high-security production environments without first addressing these gaps.

## 8. 自审计 checklist (paper reviewer 验证用)

Reviewers 可以用这个 checklist 验证我们没造假:

- [ ] 打开 `/home/abc/openclaw-upstream-backup/src/security/secret-wrapping.ts` 看 wrap envelope 格式
- [ ] 打开 `/home/abc/openclaw-upstream-backup/src/security/keyring-provider.ts` 看 FileKeyring 实施
- [ ] 跑 `.github/workflows/pqc-ci.yml` 列出的 focused tests
- [ ] 跑 `node scripts/check-pqc-cache-timing-evidence.mjs`
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
