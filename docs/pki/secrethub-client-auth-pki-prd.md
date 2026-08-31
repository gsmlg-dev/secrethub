# SecretHub 客户端认证 PKI

## 产品需求文档（PRD）

| 项目 | 内容 |
|---|---|
| 产品 | SecretHub Client Authentication PKI |
| 首版目标 | 完整替代当前 `client-ca` 运行系统 |
| 目标仓库 | `gsmlg-dev/secrethub` |
| 配套交付 | `caddy-secrethub-pki` Caddy verifier module |
| 兼容要求 | 不兼容、不导入现有 `client-ca` |
| 主要消费者 | Caddy mTLS client authentication |

---

## 1. 产品摘要

SecretHub Client Authentication PKI 用于替代当前独立运行的 `client-ca`。

管理员可以在 SecretHub 中：

- 初始化专用 Client CA；
- 创建客户端 identity；
- 签发客户端本地 CSR；
- 查看与吊销证书；
- 生成完整签名 CRL；
- 通过 SecretHub Agent 将 CA 和 CRL 分发到 Caddy host。

Caddy 只使用 Agent 管理的本地文件和 fail-closed CRL verifier。S3、Git 证书仓库和旧 `client-ca` 均不属于新系统运行时链路。

---

## 2. 问题陈述

当前 `client-ca` 可以签发证书，但它独立于 SecretHub 的以下能力：

- encrypted key storage；
- Vault seal state；
- audit；
- Agent runtime connection；
- certificate lifecycle；
- revocation 与 CRL；
- Admin UI 和统一运维状态。

Caddy 需要一个可靠的 mTLS trust source：

1. 一个只签客户端认证证书的专用 CA；
2. 一个可以及时同步、并在 TLS handshake 时离线检查的 revocation state。

SecretHub 已经拥有 Core-to-Agent 可信连接和大部分 PKI/CRL primitive，因此应将签发、吊销、CRL 与分发统一到 SecretHub 中。

---

## 3. 产品原则

1. **用途隔离**：该 CA 只签发 mTLS client certificate。
2. **私钥本地化**：client private key 由客户端生成并保留。
3. **身份由服务端决定**：SecretHub 控制 subject、SAN、EKU 和 TTL。
4. **吊销可分发**：每次成功吊销都生成新的签名 CRL。
5. **Handshake 离线**：Caddy 只使用本地 CA/CRL。
6. **Fail closed**：缺失、无效或过期 trust state 拒绝新连接。
7. **无兼容负担**：旧 `client-ca` 被替代，不被迁移或模拟。
8. **首版最小化**：一个不可变 Client CA、一个完整 CRL、一个 trust domain。

---

## 4. 用户与系统角色

### SecretHub Administrator

- 初始化 Client Authentication CA；
- 创建和 disable client identity；
- 签发 CSR；
- 下载公开证书；
- 吊销证书；
- 查看 CRL 与 Agent synchronization 状态。

### Client Operator

- 在客户端生成 private key；
- 创建 CSR；
- 将 CSR 提交给管理员；
- 将返回证书与本地 private key 配对安装。

### SecretHub Agent

- 请求最新 public trust bundle；
- 验证并原子安装 CA、CRL 和 manifest；
- 上报已应用 generation 或失败原因。

### Caddy

- 验证客户端证书链；
- 验证固定 Client Authentication profile；
- 使用本地 CRL 拒绝 revoked certificate。

---

## 5. 产品目标与成功指标

### 目标

- 不导入旧系统的前提下完整替代 `client-ca`；
- 将客户端证书生命周期统一到 SecretHub；
- 从 mTLS trust distribution 中移除 S3；
- 让管理员看到 CRL 到 Agent 的传播状态；
- Core 或网络短暂故障时，Caddy 继续使用 last-known-good。

### 成功指标

| 指标 | 目标 |
|---|---|
| 正常签发 API latency | p95 小于 2 秒 |
| Revocation commit 到在线 Agent ACK | p95 小于 30 秒 |
| Agent reconnect 到 current generation | p95 小于 30 秒 |
| Caddy 检测 CRL 更新 | 10 秒以内 |
| Core/client 之外 private-key 泄露 | 0 |
| 只有数据库 revoked、没有对应 CRL | 0 |
| 非固定 profile 证书被接受 | conformance test 中为 0 |
| Cutover 前 E2E pass rate | 100% |

---

## 6. 首版范围

首版包含：

- 一个 self-signed Client Authentication CA；
- 一个全局 `client-auth` trust domain；
- 管理员维护 client identity；
- CSR-based client certificate issuance；
- issuance idempotency；
- 同一 identity 允许多张同时有效证书，支持平滑 replacement；
- certificate revocation；
- disable identity 并一次性吊销全部 active certificate；
- complete signed CRL；
- scheduled CRL refresh；
- versioned public trust bundle；
- Core-to-Agent push notification + Agent pull synchronization；
- Agent last-known-good 与 atomic local store；
- Agent ACK 和 error status；
- Caddy companion CRL verifier；
- Admin API 与最小 LiveView UI；
- audit、telemetry、migration、测试和 clean-cut runbook。

---

## 7. 明确排除

- 导入旧 CA 或 private key；
- Cutover 后继续信任旧 `client-ca` certificate；
- 兼容旧 API、CLI、path、metadata 或证书结构；
- 产品内置 dual-trust migration；
- Root/Intermediate 层级；
- CA rotation；
- external CA；
- server certificate issuance；
- public enrollment；
- client-controlled subject/SAN；
- client private-key escrow；
- S3 或其他对象存储；
- OCSP；
- Delta CRL；
- 公共 CRL URL；
- 吊销后终止已有 TLS session；
- HSM/KMS/TPM；
- multi-tenant authority；
- self-service renewal。

---

## 8. 主要用户流程

### 8.1 初始化 authority

```text
管理员打开 Client Authentication PKI
        ↓
SecretHub 确认 Vault unsealed 且 authority 不存在
        ↓
管理员执行 initialize
        ↓
Core 创建加密 CA key、CA certificate 和 empty CRL
        ↓
Authority 以 generation 1 进入 active
```

期望结果：

- 可查看 public CA；
- private key 不被返回；
- 可查看初始 CRL number、generation 和 nextUpdate；
- Agent 可以立即开始同步。

### 8.2 签发客户端证书

```text
客户端本地生成 private key
        ↓
客户端生成 CSR
        ↓
管理员创建或选择 SecretHub client identity
        ↓
管理员提交 CSR 和可选 TTL
        ↓
SecretHub 验证 CSR，并生成 canonical certificate
        ↓
管理员下载 certificate 与 CA bundle
        ↓
客户端将 certificate 与本地 private key 配对安装
```

### 8.3 替换即将过期的证书

```text
客户端生成新 key 和 CSR
        ↓
管理员为同一 identity 签发第二张 certificate
        ↓
客户端安装并验证新 certificate
        ↓
管理员可吊销旧 certificate
```

允许同一 identity 同时存在多张 active certificate，避免 key replacement 强制中断。

### 8.4 吊销 compromised certificate

```text
管理员选择 certificate 和 reason
        ↓
Core 锁定 authority 和 certificate state
        ↓
Core 标记 certificate revoked
        ↓
Core 签名并保存新 full CRL
        ↓
事务 commit
        ↓
Core 通知在线 Agent 有新 generation
        ↓
Agent pull、验证并原子安装 bundle
        ↓
Caddy hot reload CRL
        ↓
该证书的新 TLS handshake 失败
```

### 8.5 Agent reconnect

```text
Agent 重新连接 Core
        ↓
Agent 上报 current generation
        ↓
Core 返回 not_modified 或 current bundle
        ↓
Agent 验证并安装较新 generation
        ↓
Agent ACK applied generation
```

---

## 9. 功能需求

### FR-001 — Authority initialization — P0

系统必须创建且只允许一个 active Client Authentication authority。

要求：

- 需要 administrator authorization；
- 需要 Vault unsealed；
- 默认 ECDSA P-384；
- 生成 `CA:TRUE`、`keyCertSign`、`cRLSign` 的 self-signed CA；
- CA private key 加密后才保存；
- 同时创建 initial empty CRL；
- 创建 bundle generation 1；
- 不返回 private key；
- 重复初始化返回 `409 authority_already_initialized`。

### FR-002 — Authority status — P0

系统必须展示：

- authority state；
- CA subject、canonical fingerprint 和有效期；
- certificate TTL policy；
- current CRL number；
- CRL `thisUpdate`、`nextUpdate`；
- current bundle generation；
- active identity/certificate 数量；
- Agent generation lag。

Vault sealed 时仍可读取公开状态、CA 和 CRL。

### FR-003 — Client identity — P0

管理员可以创建 client identity：

- 自动生成 UUID；
- 唯一 display name；
- active/disabled status；
- 可选非 secret metadata。

Certificate 编码 UUID，不编码可变 name 作为 canonical identity。

### FR-004 — Disable identity — P0

Disable identity 时：

- 禁止后续签发；
- 吊销该 identity 的全部 active certificate；
- 只生成一个包含所有新吊销项的 full CRL；
- 整体 transaction；
- 记录 audit。

### FR-005 — CSR validation — P0

签发服务必须：

- 只接受 PEM CSR；
- 安全解析；
- 验证 CSR signature；
- 拒绝 malformed/tampered CSR；
- 接受 RSA >= 2048；
- 接受 ECDSA P-256/P-384；
- 拒绝其他 algorithm/curve；
- 忽略 CSR subject 和 requested extension。

### FR-006 — Canonical issuance — P0

证书必须精确包含：

```text
O=SecretHub Client Authentication
CN=<identity UUID>
URI SAN=urn:secrethub:client:<identity UUID>
CA:FALSE
digitalSignature
clientAuth
```

不得包含 `serverAuth`、CA signing usage 或 client-controlled SAN。

默认 TTL 30 天，最大 TTL 90 天，且不得超过 CA expiry。

### FR-007 — Issuance idempotency — P0

每次 issuance request 必须包含 UUID `request_id`。

- 完全相同 replay 返回原 certificate；
- 同 request ID 但 CSR、identity 或 TTL 不同，返回 `409 idempotency_conflict`；
- 失败事务不消费 request ID。

### FR-008 — Certificate inspection — P0

管理员可以按以下条件查看 certificate：

- identity；
- status；
- serial；
- canonical fingerprint；
- validity；
- revocation reason；
- issuance request ID。

系统不提供任何 client private key。

### FR-009 — Certificate revocation — P0

允许的 reason：

```text
key_compromise
superseded
cessation_of_operation
privilege_withdrawn
operator_revoked
```

成功响应前必须完成：

- certificate revoked state；
- revoked_at；
- 新 CRL number；
- 新 bundle generation；
- 新 signed CRL validation 与 persistence。

重复吊销已 revoked certificate 返回现有状态，不额外生成 CRL，除非管理员显式 refresh。

### FR-010 — Complete CRL — P0

系统维护包含全部 revoked 且尚未过期 Client Authentication certificate 的完整 CRL。

CRL 必须包含：

- 与 Client CA 一致的 issuer；
- 有效 signature；
- 可用时包含 Authority Key Identifier；
- 单调递增 CRL Number；
- revocation timestamp；
- reason code；
- `thisUpdate` 与 `nextUpdate`。

### FR-011 — Scheduled CRL refresh — P0

Supervised worker 必须在 CRL 过期前生成新 CRL。

默认：

```text
refresh check: 每 6 小时，加 jitter
refresh ahead: 12 小时
CRL validity:  48 小时
```

多个 Core node 可同时运行 worker，但数据库锁必须保证只产生一个 next CRL number。

### FR-012 — Trust bundle — P0

Core 提供 deterministic public bundle：

- schema version；
- authority；
- generation；
- CA PEM 与 fingerprint；
- CRL PEM、number 与 DER fingerprint；
- `thisUpdate`、`nextUpdate`；
- bundle hash。

Generation 必须单调递增。

### FR-013 — Agent pull sync — P0

启用该功能的 Agent 在以下时机请求 current bundle：

- trusted runtime connection 成功后；
- 收到 update notification；
- 每 15 分钟，加 jitter；
- 本地 validation failure 后；
- 本机 explicit sync command。

Agent 已是 current 时，Core 返回 `not_modified`。

### FR-014 — Core push notification — P0

新 generation commit 后，Core 向在线 Agent 发送轻量 update notification。

必须复用现有 Agent runtime connection，不新建 daemon 或 transport。

Push 丢失不能影响最终一致性，因为 reconnect 与 periodic pull 会修复。

### FR-015 — Agent bundle validation — P0

以下任意验证失败时，Agent 拒绝 bundle：

- schema；
- bundle hash；
- CA parse/profile/self-signature/fingerprint；
- CRL parse/issuer/signature/number/fingerprint/freshness；
- generation monotonicity；
- CRL number monotonicity；
- 同 generation 出现不同内容。

### FR-016 — Atomic local publication — P0

Agent 必须使用 generation directory 和 atomic `current` symlink。

不得分别 in-place 更新 CA、CRL 和 manifest。

任意写入阶段 crash 后，旧 generation 必须仍可用。

### FR-017 — Last-known-good — P0

Core 不可用或新 bundle 无效时，Agent 保留 previous valid generation。

Current CRL 过期后，Agent 不再报告 PKI ready。

### FR-018 — Agent ACK — P1

成功安装后 Agent 上报：

- generation；
- CRL number；
- bundle hash；
- installed_at。

失败时上报稳定 error code 和经过脱敏的 detail。

### FR-019 — Caddy CA verification — P0

Caddy 使用 Agent-managed CA PEM 配置 `trust_pool file`。

CA 文件缺失或 malformed 时，Caddy 配置加载必须失败。

### FR-020 — Caddy CRL verifier — P0

Companion module 必须：

- 注册 `tls.client_auth.verifier.secrethub_crl`；
- 只读本地 CA/CRL；
- 使用前验证 CRL；
- 自动发现并原子加载较新 CRL；
- 拒绝 revoked certificate；
- 拒绝 stale CRL；
- enforcement `CA:FALSE`、`clientAuth`、SecretHub URI SAN；
- fail closed；
- 不访问网络。

### FR-021 — Admin UI — P1

现有 PKI 区新增 Client Authentication 页面：

- overview/status；
- identity create/disable；
- CSR submit 与 certificate download；
- certificate inspect/revoke；
- CRL status/manual refresh；
- Agent generation status。

### FR-022 — Admin API — P0

Administrator-protected JSON API 提供：

```text
authority initialize/status
identity create/list/read/disable
certificate issue/list/read/revoke
CRL refresh/read
public bundle read
Agent synchronization status
```

### FR-023 — Audit — P0

Authority、identity、issuance、revocation、CRL、Agent apply mutation 均记录 audit event，包含 correlation ID 与稳定 result code。

Audit 不得保存 private key、完整 CSR、token 或 secret plaintext。

### FR-024 — Sealed behavior — P0

Vault sealed 时：

- signing、revocation、disable-with-revocation 和 CRL refresh 失败；
- 已持久化 public bundle read 与 Agent sync 继续。

生产环境 `SealState` 缺失时 private-key operation fail closed，禁止固定 test key。

---

## 10. API 需求

### 10.1 初始化 authority

```text
POST /v1/pki/client-auth/initialize
```

```json
{
  "key_algorithm": "ecdsa_p384",
  "ca_validity_days": 1825,
  "default_ttl_seconds": 2592000,
  "max_ttl_seconds": 7776000
}
```

Response 不包含 private key。

### 10.2 创建 identity

```text
POST /v1/pki/client-auth/identities
```

```json
{
  "name": "backup-agent-amsterdam",
  "metadata": {
    "owner": "infrastructure"
  }
}
```

### 10.3 签发 certificate

```text
POST /v1/pki/client-auth/identities/:id/certificates
```

```json
{
  "request_id": "e7eb420d-5bf3-46d9-ae0e-7ab16f53fe97",
  "csr": "-----BEGIN CERTIFICATE REQUEST-----...",
  "ttl_seconds": 2592000
}
```

### 10.4 吊销 certificate

```text
POST /v1/pki/client-auth/certificates/:id/revoke
```

```json
{
  "reason": "key_compromise"
}
```

### 10.5 手工 CRL refresh

```text
POST /v1/pki/client-auth/crl/refresh
```

即使 revoked set 未变化，也生成新的 CRL number 和 generation。

### 10.6 稳定错误码

至少包含：

```text
authority_not_initialized
authority_already_initialized
authority_unavailable
vault_sealed
vault_unavailable
identity_not_found
identity_disabled
certificate_not_found
certificate_already_revoked
invalid_request_id
invalid_csr
unsupported_key
invalid_ttl
idempotency_conflict
crl_generation_failed
bundle_unavailable
forbidden
```

API error 不暴露内部 stack trace 或 cryptographic structure。

---

## 11. UI 需求

### Overview

显示：

- 未初始化时的 initialize action；
- active authority health；
- CA fingerprint 与 expiry；
- CRL number 与 expiry countdown；
- bundle generation；
- active/revoked certificate count；
- connected/lagging Agent count。

### Identity details

支持：

- identity metadata；
- CSR paste/upload；
- 受 policy 约束的 TTL；
- certificate download；
- identity 的全部 certificate；
- disable-and-revoke action。

### Certificate details

显示：

- PEM download；
- canonical fingerprint；
- serial；
- URI SAN；
- issuer；
- validity；
- revocation state/reason；
- identity 与 issuance request。

### Distribution status

显示 Agent capability、applied generation、current desired generation、last applied time 和 error code。

---

## 12. 非功能需求

### NFR-001 — Security

- private-key operation 需要 Vault unsealed；
- CA key encrypted at rest；
- 无 private-key export endpoint；
- strict CSR/profile validation；
- Caddy fail closed；
- Agent atomic store；
- 新授权只使用 canonical fingerprint。

### NFR-002 — Availability

- Caddy handshake 无网络依赖；
- Agent 使用 last-known-good；
- Core sealed 时 public bundle 仍可读取；
- lost push 由 periodic sync 修复。

### NFR-003 — Consistency

- issuance idempotent；
- revocation 与 CRL transactional；
- multi-Core 下 CRL number/generation 单调；
- Agent 不自动 rollback。

### NFR-004 — Performance

- Caddy verifier 使用 in-memory revoked serial index；
- handshake 完成时不执行 file/network I/O；
- CRL 只在启动或文件变化时解析；
- `not_modified` 减少传输与磁盘写入。

### NFR-005 — Operability

- UI/API 可查看状态；
- 稳定 audit 与 telemetry；
- 明确 readiness；
- 可行动的 Agent error code；
- clean cutover 与 rollback runbook。

### NFR-006 — Portability

- Certificate 与 CRL 必须通过 OpenSSL 验证；
- Caddy 使用 PEM；
- 标准 TLS client 可使用 RSA 或 ECDSA client key。

---

## 13. Security Release Blocker

发布前必须完成：

1. 修复生产环境 `SealState` 缺失时固定 fallback key；
2. CA-generation HTTP response 不再返回 private key；
3. Client Authentication issuer 不调用 generic CSR signer；
4. CSR signature validation mandatory；
5. canonical DER fingerprint 一致使用；
6. 独立验证 CRL signature 与 freshness；
7. Caddy 对所有 missing/invalid trust file fail closed。

---

## 14. Acceptance Criteria

### Authority

- [ ] 初始化生成一个有效独立 CA 和 empty CRL。
- [ ] 数据库只存 encrypted CA key，不存 plaintext PEM。
- [ ] API/UI 永不暴露 CA private key。
- [ ] 重复初始化被拒绝。

### Issuance

- [ ] 有效本地 CSR 生成 OpenSSL/Caddy 可接受证书。
- [ ] Tampered CSR 被拒绝。
- [ ] Weak/unsupported key 被拒绝。
- [ ] CSR CN/SAN/EKU 不进入最终 certificate。
- [ ] Certificate 只有 canonical client profile。
- [ ] Idempotent replay 返回同一 certificate。
- [ ] Conflicting replay 被拒绝。

### Revocation 与 CRL

- [ ] 吊销使 CRL number 和 generation 各加一。
- [ ] CRL 持久化前不返回成功。
- [ ] CRL signature 对 Client CA 有效。
- [ ] Revoked serial 存在于 CRL。
- [ ] Concurrent revocation 不复用 CRL number。
- [ ] `nextUpdate` 前自动 refresh。

### Agent

- [ ] 新连接的 enabled Agent 安装 current generation。
- [ ] Push notification 触发立即 reconciliation。
- [ ] Invalid/stale/rollback bundle 被拒绝。
- [ ] Atomic-store fault injection 保留旧 current generation。
- [ ] Core outage 时 Agent 继续提供 last-known-good。
- [ ] Agent 上报 applied generation。

### Caddy

- [ ] 无 client certificate 时拒绝。
- [ ] 有效 SecretHub client certificate 被接受。
- [ ] Cutover 后旧 `client-ca` certificate 被拒绝。
- [ ] 由其他 SecretHub CA 签发的证书被拒绝。
- [ ] 吊销后新 handshake 被拒绝。
- [ ] CRL 过期后新 handshake 被拒绝。
- [ ] Invalid CRL replacement 不替换 current valid CRL。
- [ ] CRL 更新无需完整 Caddy config reload 即生效。

### Operations

- [ ] UI 显示 authority、certificate、CRL 和 Agent 状态。
- [ ] 所有 mutation 有 audit event。
- [ ] Production-like E2E 通过。
- [ ] Cutover runbook 已验证。
- [ ] Runtime architecture/config 中不存在 S3。

---

## 15. 交付 Milestone

### Milestone A — PKI hardening 与 schema

交付：

- fail-closed seal-state；
- private-key response removal；
- migration/schema；
- canonical fingerprint enforcement。

退出条件：新 authority initialization 不依赖 unsafe legacy path。

### Milestone B — Core lifecycle

交付：

- authority initialization；
- identity management；
- canonical CSR issuance；
- certificate inspection；
- issuance idempotency；
- API 与 unit test。

退出条件：OpenSSL 验证签发证书成功。

### Milestone C — CRL lifecycle

交付：

- transactional revocation；
- full CRL manager；
- scheduled refresh；
- trust-bundle builder；
- concurrency/failure test。

退出条件：成功响应前，revoked serial 已进入 verified signed CRL。

### Milestone D — Agent distribution

交付：

- Channel pull/push/ACK/error；
- Core runtime push bridge；
- Agent manager；
- validation 与 atomic store；
- status reporting。

退出条件：Agent 收敛到 current generation，并通过 write fault test。

### Milestone E — Caddy enforcement

交付：

- `caddy-secrethub-pki` verifier；
- custom Caddy build/package；
- Caddyfile integration；
- hot CRL reload；
- fail-closed test。

退出条件：E2E revocation 阻止新 TLS handshake。

### Milestone F — UI、运维与替代

交付：

- LiveView；
- distribution status；
- deployment/cutover runbook；
- production-like E2E；
- clean switch from `client-ca`。

退出条件：独立 `client-ca` runtime 不再需要。

---

## 16. Cutover Requirement

产品不提供 compatibility layer。Cutover 必须：

1. 初始化 SecretHub Client Authentication CA；
2. 为全部 active client 签发新 certificate；
3. 在客户端安装新 certificate；
4. 在 Caddy host 同步 SecretHub Agent trust bundle；
5. 验证 CA、CRL 和 manifest；
6. 启动包含 companion module 的 custom Caddy；
7. 验证新 certificate 成功；
8. 验证旧 `client-ca` certificate 失败；
9. 吊销测试 certificate 并验证传播；
10. 停止和移除独立 `client-ca` runtime。

无需导入旧 CA key 或 certificate record。

---

## 17. 风险与缓解

| 风险 | 缓解 |
|---|---|
| Core 长时间故障导致 CRL 过期 | 48h validity、12h refresh-ahead、清晰告警 |
| Agent 写入部分文件 | generation directory、fsync、atomic symlink |
| Push 丢失 | reconnect + 15min reconciliation |
| Bundle rollback | generation/CRL monotonic check |
| 新 CRL malformed | 安装前验证并保留 last-known-good |
| Caddy 内存 CRL 滞后 | poll current file/symlink，并在 handshake 检查 `nextUpdate` |
| 已有长连接在吊销后继续 | 明确限制；必要时由 upstream 主动断开 |
| 多 Core node 竞争 CRL | DB row lock + unique constraint |
| Legacy controller 暴露 CA key | 新 API 不返回，并将旧行为作为 release blocker 修复 |
| Caddy/plugin version mismatch | Nix reproducible build 固定 Caddy 与 plugin 并在 CI 联合测试 |

---

## 18. Definition of Done

首版完成必须同时满足：

```text
SecretHub 初始化并保护独立 Client Authentication CA。
Client private key 始终保留在客户端。
SecretHub 签发 canonical clientAuth certificate。
Revocation 原子生成并持久化新的 signed CRL。
SecretHub Agent 验证并原子安装 CA 与 CRL。
Caddy 使用这些本地文件，并在无在线 lookup 的情况下拒绝 revoked client。
Core → Agent → Caddy 全链路有真实 E2E test。
旧 client-ca 不被导入、模拟或继续依赖。
S3 不在 mTLS trust path 中。
```
