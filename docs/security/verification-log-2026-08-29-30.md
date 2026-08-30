# PQC Fork Verification Log (2026-08-29 ~ 2026-08-30)

> **目的**: paper reviewer 复现依据, 记录 8/29 M6.B OsKeyring 真部署 + 8/30 AES-256-GCM cache-timing 补全 两件 paper-grade work 的验证步骤, 引用 commit hash + 工具 + 关键发现.
>
> **范围**: 仅 8/29 + 8/30 这 2 天累计 paper claim 从 26 ops / 127.6K 升到 28 ops / 129.2K 的验证细节. 8/25-8/28 之前的 work 见对应 commit message.
>
> **关联**: 白皮书 `pqc-whitepaper.md` §5.1.4 + §6.3 + §9.1.2 + §10. handoff prompt `pqc-fork-handoff-prompt.md` (8/30 更新). 14 个 JSON 报告在 `pqc-fork-scripts/ct-reports/{algo}_{op}/report.json`.

---

## 1. 8/29 M6.B OsKeyring 真部署 100%

**Commits**: `1cdc49a73f` (主) + `d726df2f72` (前置, 8/28 收尾 20%) + `21bc128b6b` (8/25 OsKeyring class)

**目标**: M6.B OsKeyring 从 "stub, fail-closed" 升到 "production-validated 100%". `@napi-rs/keyring` 1.3.0 dynamic load, 走 macOS Keychain / Windows Credential Manager / Linux Secret Service (libsecret + gnome-keyring).

### 1.1 环境 (WSL2 + Ubuntu + WSLg)

```bash
# WSL2 + Ubuntu (default 22.04 / 24.04)
# WSLg enabled (默认 Windows 11 22H2+): DISPLAY=:0, WAYLAND_DISPLAY=wayland-0
echo $DISPLAY             # → :0
echo $WAYLAND_DISPLAY     # → wayland-0

# 装 OS keyring backend
sudo apt install -y libsecret-1-0 gnome-keyring
# Python 包装 D-Bus Secret Service (避免直接 gdbus call hang)
pip install secretstorage   # 3.3.1
```

### 1.2 4 步 debug 突破 (从 0 到 production)

**Bug 1: Interface name 区分大小写**

```bash
# ❌ 错误: lowercase 's' in 'secrets'
gdbus call --session --dest org.freedesktop.secrets \
  --object-path /org/freedesktop/secrets \
  --method org.freedesktop.secrets.Service.CreateSession
# → No such interface 'org.freedesktop.secrets.Service'

# ✅ 正确: uppercase 'S' in 'Secret'
gdbus introspect --session --dest org.freedesktop.secrets \
  --object-path /org/freedesktop/secrets \
  --recurse
# → 看到 'org.freedesktop.Secret.Service' (大写 S)
```

**Bug 2: CreateItem 在 Collection, 不在 Service**

```bash
# Service interface 没有 CreateItem method (standard spec)
# gnome-keyring 实际把 CreateItem 放在 Collection interface

gdbus call --session --dest org.freedesktop.secrets \
  --object-path /org/freedesktop/secrets/collection/login \
  --method org.freedesktop.Secret.Collection.CreateItem \
  "{...dict...}" "{...props...}"
```

**Bug 3: @napi-rs/keyring attribute 名是 `application`+`username` (keytar 兼容 API)**

```bash
# 误以为是 service+account (Rust keyring-rs 内部用 secret_service 模块)
# 实际: keytar 兼容, attribute 名是 application + username
# 验证: 写一个 entry, 用 secretstorage lib 列 attributes
python3 -c "
import secretstorage
conn = secretstorage.dbus_init()
for coll in conn.get_all_collections():
    for item in coll.get_all_items():
        attrs = item.get_attributes()
        print(item.get_label(), attrs)
"
# → {'application': 'openclaw', 'username': 'wrap-key-2026-08', ...}
```

**Bug 4: 32 raw bytes null byte 截断**

```bash
# @napi-rs/keyring 返回 C string (null-terminated)
# 32 字节 raw AES-256 key 任何位置有 0x00 会被截断
# 修法: 存 base64url 字符串 (44 chars, 无 null byte)
# fork 的 os-keyring.ts decodeKeyMaterial 期望 base64url 字符串:
#   Buffer.from(encoded, "base64url") → 32 字节
```

### 1.3 5 步部署 (production-validated)

```bash
# 1. Persistent dbus session (NOT dbus-run-session, subshell 退出会杀 daemon)
RUNTIME_DIR="$HOME/.cache/keyring-runtime"
mkdir -p "$RUNTIME_DIR/keyring" && chmod 700 "$RUNTIME_DIR" "$RUNTIME_DIR/keyring"
DBUS_FILE="/tmp/dbus-pqc-fork-$$"
dbus-daemon --session --nofork --address="unix:path=$DBUS_FILE" --print-address \
  > /tmp/dbus-pqc-fork.addr 2>&1 &
disown
sleep 1
DBUS_ADDR=$(cat /tmp/dbus-pqc-fork.addr)
echo "DBUS_SESSION_BUS_ADDRESS=$DBUS_ADDR"
echo "XDG_RUNTIME_DIR=$RUNTIME_DIR"
echo "GNOME_KEYRING_CONTROL=$RUNTIME_DIR/keyring"

# 2. gnome-keyring-daemon (跟 dbus session 强耦合)
DBUS_SESSION_BUS_ADDRESS="$DBUS_ADDR" XDG_RUNTIME_DIR="$RUNTIME_DIR" \
  gnome-keyring-daemon --daemonize --start --components=secrets
sleep 2

# 3. Python secretstorage 写 wrap key (base64url 字符串 + application/username attrs)
#    wrap-key content = base64url(32 random bytes), e.g. "A4JR7xCupHMUVHNLMsz1/it1GLPCT7K/79lg4acJmVM="
python3 write-key-correct.py
#    write-key-correct.py: secretstorage lib 写 (label, application='openclaw', username='wrap-key-2026-08')

# 4. 启 fork 走 OsKeyring path
nohup env \
  XDG_RUNTIME_DIR="$RUNTIME_DIR" \
  DBUS_SESSION_BUS_ADDRESS="$DBUS_ADDR" \
  GNOME_KEYRING_CONTROL="$RUNTIME_DIR/keyring" \
  OPENCLAW_STATE_DIR=/home/abc/openclaw-fork \
  OPENCLAW_WRAP_KEY_OS_SERVICE=openclaw \
  OPENCLAW_WRAP_KEY_OS_ACCOUNT=wrap-key-2026-08 \
  OPENCLAW_WRAP_KEY_OS_ID=wrap-key-2026-08 \
  OPENCLAW_WRAP_KEY_FILE=/home/abc/openclaw-fork/wrap-key.bin \
  OPENCLAW_WRAP_KEY_ID=wrap-key-2026-08 \
  OPENCLAW_GATEWAY_TOKEN=lobster-pqc-v3 \
  node /home/abc/openclaw-fork-v3/dist/index.js gateway \
  > /tmp/fork-oskeyring-final.log 2>&1 &
disown
```

### 1.4 验证 PQC event log (production success marker)

```bash
# fork 启动后立刻看 log, 找 [PQC] unwrap-secret / device-identity 标记
grep -E '\[PQC\] (unwrap-secret|device-identity)' /tmp/fork-oskeyring-final.log
```

**期望输出** (8/29 验证):
```
[PQC] unwrap-secret status:ok keyId:wrap-key-2026-08 byteLength:4032
[PQC] device-identity status:ok identityKey:primary detail:unwrapped stored identity
```

- `byteLength 4032` = ML-DSA-65 私钥大小 (32 + 4032-32 = wrapped envelope, 跟 FileKeyring path 一样的结果, 但 source 是 OS keyring)
- `device-identity status:ok` = unwrap 后用 ML-DSA-65 私钥成功 verify device payload

### 1.5 Composite keyring 描述

Fork 默认 `CompositeKeyring([OsKeyring, FileKeyring])`:
- OS 优先 (active source)
- File fallback (recovery 备份)
- OS 失败降级 file, 期间零 downtime
- 适合 migration window (file → OS transition 期间)

### 1.6 老坑 (8/29 验证)

- `/run/user/1000` 是 tmpfs, 每次 shell restart 被擦 → 改用 `$HOME/.cache/keyring-runtime`
- `gnome-keyring-daemon` 跟 dbus session 强耦合 → 必须 persistent `dbus-daemon --session --nofork` (不能 `dbus-run-session`)
- `dbus-launch` 启的 session bus 启 daemon 失败 (silent) → 必须自己 dbus-daemon
- 真 OS keyring 部署在 WSL2 headless + WSLg (DISPLAY=:0) 够用, 不需要真 Linux desktop

---

## 2. 8/30 AES-256-GCM cache-timing 单独测

**Commit**: `b12aa7ad43` (whitepaper 5 处改, AES-GCM cache-timing 补全 entry)

**目标**: 7 hot paths (AES-GCM + ML-DSA 全部 3 param set + ML-KEM 全部 3 param set) × 2 test types (user-space + cache-timing) **均匀覆盖**. 之前 12 cache-timing ops 只覆盖 FIPS 203/204, AES-GCM 走 OpenSSL 3.x FIPS 140-3 path 没单独测 cache-timing (作为 "假设是" 在 §6.3 honest list). 8/30 补全 2 ops.

### 2.1 工具 (跟 12 ML algos 同一 protocol)

| 文件 | 作用 |
|------|------|
| `pqc-fork-scripts/cache-timing-ct-aesgcm.mjs` | per-process cache miss counter (under valgrind callgrind) |
| `pqc-fork-scripts/cache-timing-ct-runner-aesgcm.sh` | K=20 process/class × N=20 ops bash wrapper, 复用 callgrind |
| `pqc-fork-scripts/cache-timing-ct-driver-aesgcm.sh` | wrap + unwrap 顺序 driver (~26 min total) |
| `pqc-fork-scripts/start-aesgcm-ct.sh` | nohup background launcher (避免 bash tool 30s timeout) |

**AES-GCM class-bit choices** (跟 ML 系列一致):
- `wrap`: bit 0 of plaintext[0] (per-op fresh IV)
- `unwrap`: bit 0 of ciphertext[0] (fixed IV, class bit forced after wrap; auth tag fails as expected, bulk AES-CTR work in `update()` before auth check)

### 2.2 跑法

```bash
# Smoke test (no valgrind, 1 process, 5 ops)
rm -rf /tmp/ct-aesgcm-smoke && mkdir -p /tmp/ct-aesgcm-smoke
for op in wrap unwrap; do
  for cls in 0 1; do
    node /home/abc/pqc-fork-scripts/cache-timing-ct-aesgcm.mjs \
      --op $op --class $cls --seed 42 --ops 5 --out-dir /tmp/ct-aesgcm-smoke
  done
done
ls /tmp/ct-aesgcm-smoke/  # 4 done.* files (1 per (op, class) combination)

# Full driver (valgrind, 80 processes, 8.75 min)
bash /home/abc/pqc-fork-scripts/start-aesgcm-ct.sh
# log: /tmp/aesgcm-ct-run.log
# PID: /tmp/aesgcm-ct-run.pid
```

### 2.3 跑结果 (8/30 12:40:20 → 12:49:05, 8m 45s)

```bash
# Driver output tail
tail -3 /tmp/aesgcm-ct-run.log
# === [aes_gcm unwrap] analyzed ===
# === AES-GCM CACHE-TIMING DONE 12:49:05 ===
```

**JSON 报告** (在 `pqc-fork-scripts/ct-reports/aes_gcm_{wrap,unwrap}/report.json`):

| algo_op | K | max \|t\| | event | leak |
|---------|---|----------|-------|------|
| aes_gcm_wrap | 20 | -1.028 | DLmr | ✓ ok |
| aes_gcm_unwrap | 20 | 1.808 | D1mr | ✓ ok |

**Per-process cache event counts** (mean of K=20/class, 8/30 实测):
- L1 I-miss: 820K (wrap) / 887K (unwrap)
- L1 D-miss: 400K (wrap) / 445K (unwrap)
- L1 D-write-miss: 207K (wrap) / 221K (unwrap)
- L3 I-miss: 35K (wrap) / 37K (unwrap)
- L3 D-miss: 62K (wrap) / 62K (unwrap) ← 跟 12 ML algos 同量级
- L3 D-write-miss: 128K (wrap) / 137K (unwrap)

### 2.4 累计 paper claim (8/30 升级)

| 维度 | 8/29 之前 | 8/30 之后 |
|------|-----------|-----------|
| Hot paths × 2 test types 均匀覆盖 | 6 (FIPS 203/204) + AES-GCM 假设 | 7 全部 0 leak |
| Cache-timing ops | 12 (12 ML) | 14 (12 ML + 2 AES-GCM) |
| Cache-timing op count | 9.6K | 11.2K (新增 1.6K) |
| Total ops (user-space + cache-timing) | 127.6K | 129.2K |
| max \|t\| cache-timing | 1.983 (ML-DSA-44 verify Ir) | 1.983 (旧) / 1.808 (AES-GCM unwrap D1mr, 新) |
| Threshold | 4.5 | 4.5 |

### 2.5 Regression guard (防未来 stale)

```bash
bash /home/abc/pqc-fork-scripts/check-cache-timing-claims.sh
```

**期望输出** (8/30 验证):
```
algorithm_op            K     max|t|    event   leak
------------------------------------------------------------
aes_gcm_unwrap          K=20  1.808     D1mr    ✓ ok
aes_gcm_wrap            K=20  -1.028    DLmr    ✓ ok
ml_dsa44_sign           K=20  0.629     DLmr    ✓ ok
... (12 more)
------------------------------------------------------------
Total: 14, Pass: 14, Fail: 0
Cumulative paper claim: 14 ops cache-timing 0 leak (threshold |t| < 4.5)

✓ PASS: all 14 cache-timing reports claim is consistent (0 leak, max |t| < 4.5).
```

`exit 0` if all pass, `exit 1` if any report shows leak (e.g. 阈值 < 4.5 失败 / overall.leak=true).

---

## 3. 累计 paper claim (8/30 升级最终)

| | 8/29 之前 | 8/30 升级 | 增量 |
|---|-----------|-----------|------|
| Hot paths × test types | 6 ML × 2 + AES-GCM × 1 = 13 cells | 7 hot paths × 2 = 14 cells | +1 cell (AES-GCM cache-timing) |
| Cache-timing ops | 12 (3 ML-DSA × 2 + 3 ML-KEM × 2) | 14 (上面 + 2 AES-GCM) | +2 ops |
| Cache-timing op count | 9.6K (12 × 800) | 11.2K (14 × 800) | +1.6K ops |
| **User-space + cache-timing total ops** | 127.6K (40 + 18 + 60 + 9.6) | **129.2K** (40 + 18 + 60 + 11.2) | +1.6K ops |
| max \|t\| cache-timing | 1.983 (ML-DSA-44 verify Ir) | 1.983 (旧) / 1.808 (AES-GCM unwrap, 新) | 旧 max 不变 |
| Threshold | 4.5 | 4.5 | — |
| M6.B deployment | FileKeyring fallback (80%) | **OsKeyring + FileKeyring composite 100%** | +20% |

---

## 4. 引用

- **白皮书**: `docs/security/pqc-whitepaper.md`
  - §2.2.5.B (M6.B 部署状态, 8/29 验证)
  - §5.1.4 (cache-timing protocol)
  - §6.3 (剩余风险与缓解)
  - §9.1.2 (side-channel test table)
  - §10 (未来工作 — per-op cache-timing 仍 P0)
- **Handoff prompt** (8/30 更新): `pqc-fork-scripts/pqc-fork-handoff-prompt.md` + `pqc-fork-handoff-prompt-part2-ops.md`
- **Cache-timing reports** (14 个 JSON): `pqc-fork-scripts/ct-reports/{algo}_{op}/report.json`
- **Cache-timing scripts** (新增 AES-GCM): `pqc-fork-scripts/cache-timing-ct-aesgcm.mjs` + `cache-timing-ct-runner-aesgcm.sh` + `cache-timing-ct-driver-aesgcm.sh`
- **Regression guard**: `pqc-fork-scripts/check-cache-timing-claims.sh` (新)
- **WSL local main 16 commits** (8/25 ~ 8/30): 等 push (用户启 FlClash + corp proxy 后)

## 5. 8/30 ~ 8/31 next backlog

- **P0 mlock Node 24.6+** (2-3 天, 需 user 中途 sync 确认): Node 22 → 24.6+ 升级, 全 KAT 174/174 回归, 28 ops side-channel 回归
- **P0 per-op cache-timing** (98h CPU, 14 algo × 5000 ops × 2 class): SIGUSR1/SIGUSR2 dump+zero, valgrind 50x 慢
- **P0 第三方 cryptographer audit** (4-6 周 + 钱): paper-grade 强要求
- **P1 AES-NI 硬件 timing** (1 天, 需 Intel perf counter)
- **P1 BoringSSL TLS 1.3 hybrid** (1 周, X25519+ML-KEM-768)

---

**日志时间**: 2026-08-30 20:04 北京, 16 commits in WSL local main, 等 push.
