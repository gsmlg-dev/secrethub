# SecretHub 客户端认证 PKI

## 系统架构与设计规范

| 项目 | 内容 |
|---|---|
| 状态 | 待实现设计稿 |
| 目标仓库 | `gsmlg-dev/secrethub` |
| 审查基线 | `main`，commit `79b615f82075060417272a8e703a68aebc55a9b9`（`v1.0.0-rc10`） |
| 替代对象 | 当前正在运行的独立 `client-ca` 系统 |
| 兼容策略 | 直接替换，不兼容旧 API、数据、证书、CLI 或目录结构 |
| 运行时分发 | SecretHub Core → SecretHub Agent → Caddy 本地文件 |
| 对象存储 | 不使用 S3 或其他对象存储 |

---

## 1. 摘要

SecretHub 新增一个专用的 **Client Authentication PKI** 子系统，成为 Caddy mTLS 客户端证书的唯一签发与吊销权威。

系统严格分为三个安全域：

```text
SecretHub Core
  持有并使用 Client CA 私钥
  签发客户端证书
  记录证书吊销状态
  生成并签名完整 CRL

SecretHub Agent
  通过现有可信运行时连接接收公开 CA 和 CRL
  验证并保存 last-known-good trust bundle
  以本地只读文件形式提供给 Caddy

Caddy
  使用本地 Client CA 验证客户端证书链
  使用本地签名 CRL 拒绝已吊销证书
```

当前 `client-ca` 只是临时运行系统。SecretHub 不导入其 CA 私钥、已签发证书、序列号、元数据、API、仓库结构或脚本接口。切换时重新由 SecretHub 签发证书，在客户端安装新证书，然后让 Caddy 改用 SecretHub Agent 提供的 CA 与 CRL。

首版有意限制为：

- 一个独立、不可变、自签名的 Client Authentication CA；
- 一个完整 CRL；
- 一个全局 `client-auth` trust domain；
- 不实现 Root/Intermediate 层级；
- 不实现 CA 轮换；
- 不实现 OCSP、Delta CRL、公共注册协议或远端对象存储。

---

## 2. 现有基础

SecretHub 当前已经具备大部分必要能力：

- Vault seal state 保护下的 CA 私钥加密存储；
- X.509 证书与 CSR 解析；
- App certificate 的严格 canonical issuance；
- Agent certificate enrollment；
- 证书生命周期与审计记录；
- `apps/x509` 中完整的 CRL 生成、解析、PEM/DER 编解码、CRL Number 与签名验证；
- Core 与 Agent 之间持续存在的可信 mTLS WebSocket Channel；
- Core 侧运行时连接注册表和 `send_to_agent/2`；
- Agent 侧对 Phoenix Channel server push event 的接收能力。

新功能应复用这些能力，但不能继续扩展旧的通用 `CA.sign_csr/4` 路径。该旧路径的 CSR 校验和证书 profile 不如当前 App PKI 严格，不适合作为新的 mTLS Client CA 签发入口。

相关现有模块：

```text
apps/secrethub_core/lib/secrethub_core/pki/ca.ex
apps/secrethub_core/lib/secrethub_core/pki/csr.ex
apps/secrethub_core/lib/secrethub_core/pki/certificate_identity.ex
apps/secrethub_core/lib/secrethub_core/pki/app_certificates.ex
apps/secrethub_core/lib/secrethub_core/agents/connection_manager.ex
apps/secrethub_web/lib/secret_hub/web/channels/agent_runtime_channel.ex
apps/secrethub_agent/lib/secrethub_agent/connection.ex
apps/x509/lib/x509/crl.ex
apps/x509/lib/x509/crl/entry.ex
apps/x509/lib/x509/crl/extension.ex
```

---

## 3. 目标

系统必须提供：

1. 一个只签发 mTLS 客户端证书的独立 Client CA。
2. 客户端本地生成私钥和 CSR，SecretHub 只负责校验 CSR 与签发。
3. 使用 URI SAN 表达稳定客户端身份。
4. 客户端身份、证书查看、重新签发与吊销。
5. 单调递增版本的完整签名 CRL。
6. 通过现有 SecretHub Agent 运行时连接自动同步公开 trust bundle。
7. Agent 原子发布 CA、CRL 与 manifest 本地文件。
8. Caddy 侧 fail-closed CRL enforcement。
9. 完整审计、状态观测和端到端测试。
10. 从当前 `client-ca` 直接切换并彻底替代。

---

## 4. 非目标

首版不实现：

- 导入或继续信任旧 `client-ca` CA；
- 保留旧证书、序列号或证书记录；
- 兼容旧脚本、API、CLI、仓库或文件路径；
- S3、Caddy Storage、Git、Consul 等远端 trust distribution backend；
- Root CA + Intermediate CA 层级；
- CA 私钥通过 HTTP API 导出；
- CA 轮换；
- OCSP；
- Delta CRL；
- 公共 CRL Distribution Point；
- ACME、EST、SCEP；
- 匿名或自助 enrollment；
- TPM、HSM、KMS、设备证明；
- 吊销后强制关闭已经建立的 TLS 长连接；
- TLS server certificate 签发；
- 多租户通用 PKI 平台。

---

## 5. 核心架构决策

### 5.1 独立 trust domain

该功能拥有一个全局 authority：

```text
client-auth
```

它不得复用 SecretHub Agent、Application、Admin 或 Server TLS 所使用的 CA。

Caddy 只信任该 Client Authentication CA，因此其他 SecretHub PKI 证书即使合法，也不能通过此 mTLS 入口。

### 5.2 首版 CA 不可变

初始化后，以下内容不可修改：

- CA subject；
- CA key algorithm；
- CA private key；
- CA certificate。

替换 CA 是一个显式破坏性操作，不属于首版。

这一限制使 Caddy 的 CA trust pool 在正常运行期间保持不变；只有 CRL 持续更新。

### 5.3 客户端私钥永远不进入 SecretHub

客户端自行生成 private key 和 CSR。SecretHub：

1. 校验 CSR 签名；
2. 提取 public key；
3. 忽略 CSR 中客户端请求的 subject 与 extensions；
4. 由服务端生成最终证书身份与用途。

SecretHub 不能：

- 生成客户端私钥；
- 接收客户端私钥；
- 返回客户端私钥；
- 存储客户端私钥；
- 在日志中记录任何私钥材料。

### 5.4 Core 是权威，Agent 是分发器

Agent 不具备任何签发能力。Agent 只保存：

- 公开 CA certificate；
- 已签名 CRL；
- manifest、hash 和 generation。

CA 私钥只存在于 SecretHub Core 的加密存储中，并且只有在 Vault unsealed 时才允许解密使用。

### 5.5 只使用完整 CRL

每个 CRL 包含该 CA 已签发且尚未自然过期的全部已吊销客户端证书。

CRL 在以下情况重新生成：

- 成功吊销证书时；
- disable identity 并吊销其活动证书时；
- 当前 CRL 接近 `nextUpdate` 时；
- 管理员手工触发 refresh 时。

### 5.6 Fail closed

以下情况必须拒绝新的 mTLS handshake：

- Caddy 启动时 CA 文件缺失或格式错误；
- Caddy 启动时 CRL 文件缺失或格式错误；
- 找不到与证书 issuer 匹配的 CRL；
- CRL 签名无效；
- CRL `thisUpdate` 明显位于未来；
- 当前时间已超过 `nextUpdate`；
- 客户端证书 serial 存在于 CRL；
- 客户端证书不符合固定 Client Authentication profile。

### 5.7 TLS handshake 无在线依赖

Caddy 在 TLS handshake 中不得访问 SecretHub Core、SecretHub Agent、数据库或网络 API。

Core 或网络短暂故障时，只要 Agent 保存的 last-known-good CRL 仍未过期，Caddy 可继续完成新的客户端认证。

---

## 6. 总体架构

```text
                                      Admin API / LiveView
                                              │
                                              ▼
┌──────────────────────────────────────────────────────────────────────┐
│                         SecretHub Core                               │
│                                                                      │
│  ClientAuth.Authority          ClientAuth.Issuer                     │
│  ClientAuth.Identities         ClientAuth.CRLManager                 │
│  ClientAuth.TrustBundle        ClientAuth.Notifier                   │
│                                                                      │
│  PostgreSQL                                                          │
│  ├── 加密 Client CA private key                                      │
│  ├── CA 与 leaf certificate record                                   │
│  ├── client identity                                                  │
│  ├── immutable CRL generation                                         │
│  ├── issuance idempotency record                                      │
│  └── Agent bundle receipt                                             │
└────────────────────────────────┬─────────────────────────────────────┘
                                 │ 现有 mTLS Agent runtime channel
                                 │
                                 │ push: pki:client_auth_bundle:updated
                                 │ pull: pki:client_auth_bundle:get
                                 ▼
┌──────────────────────────────────────────────────────────────────────┐
│                         SecretHub Agent                              │
│                                                                      │
│  PKI.TrustBundleManager                                              │
│  ├── 请求最新 generation                                             │
│  ├── 验证 CA、CRL 与 manifest                                        │
│  ├── 拒绝 rollback                                                    │
│  ├── 原子写入 generation                                              │
│  └── 向 Core ACK                                                      │
│                                                                      │
│  /var/lib/secrethub/pki/client-auth/                                 │
│  ├── watermark.json                                                  │
│  └── current/                                                        │
│      ├── ca.crt                                                      │
│      ├── crl.pem                                                     │
│      └── manifest.json                                               │
└────────────────────────────────┬─────────────────────────────────────┘
                                 │ 本地只读文件
                                 ▼
┌──────────────────────────────────────────────────────────────────────┐
│                              Caddy                                   │
│                                                                      │
│  trust_pool file: ca.crt                                             │
│  verifier: tls.client_auth.verifier.secrethub_client_auth            │
│  CRL: 文件变化后验证并原子替换内存状态                               │
└────────────────────────────────┬─────────────────────────────────────┘
                                 │ 已认证 HTTP 请求
                                 ▼
                            Upstream Service
```

---

## 7. PKI Profile

### 7.1 Client Authentication CA

首版生成一个 self-signed CA：

```text
Subject:
  O=SecretHub
  CN=SecretHub Client Authentication CA

Basic Constraints:
  critical
  CA:TRUE

Key Usage:
  critical
  keyCertSign
  cRLSign

Subject Key Identifier:
  present

Authority Key Identifier:
  present，指向自身
```

默认值：

```text
Key algorithm: ECDSA P-384
Validity:      5 years
Signature:     ECDSA with SHA-384
```

首版可选支持 RSA-4096，但不得支持其他 CA algorithm 或 key size。初始化后算法不可变。

### 7.2 客户端证书

SecretHub 完全控制最终 certificate profile，不复制 CSR subject 或 requested extensions。

```text
Subject:
  O=SecretHub Client Authentication
  CN=<client identity UUID>

Basic Constraints:
  CA:FALSE

Key Usage:
  critical
  digitalSignature

Extended Key Usage:
  clientAuth

Subject Alternative Name:
  URI:urn:secrethub:client:<client identity UUID>
```

客户端证书不得包含：

```text
serverAuth
keyCertSign
cRLSign
CA:TRUE
客户端自行指定的 DNS SAN
客户端自行指定的其他 URI SAN
```

默认生命周期：

```text
Default TTL: 30 days
Maximum TTL: 90 days
Clock skew:   5 minutes
```

接受的客户端 public key：

```text
RSA:   modulus >= 2048 bits，odd exponent >= 3
ECDSA: P-256 或 P-384
```

Leaf certificate 的 `notAfter` 不得超过 CA 的 `notAfter`。

### 7.3 Fingerprint

所有新的认证与授权 fingerprint 统一使用：

```text
SHA-256(exact DER certificate bytes)
→ lowercase hexadecimal
→ exactly 64 characters
→ no prefix
→ no separators
```

旧的 PEM hash、带冒号 fingerprint 或 `sha256:` 前缀不得用于新的授权判断。

### 7.4 Serial number

使用 `:crypto.strong_rand_bytes/1` 生成随机正 160-bit serial，并由数据库唯一约束保证不重复。

---

## 8. 数据模型

### 8.1 `client_auth_authorities`

首版为 singleton authority record。

```text
id                     UUID
slug                   固定为 "client-auth"
name                   显示名称
status                 initializing | active | disabled | failed
ca_certificate_id      FK -> certificates
current_crl_id          FK -> client_auth_crls
current_generation     bigint，单调递增
current_crl_number     bigint，单调递增
key_algorithm          ecdsa_p384 | rsa_4096
default_ttl_seconds    integer
max_ttl_seconds        integer
inserted_at
updated_at
```

约束：

- 只能有一个 active `client-auth` authority；
- active 时 `current_generation >= 1`；
- active 时 `current_crl_number >= 1`；
- active authority 必须引用有效 CA certificate 和 current CRL。

### 8.2 `client_auth_identities`

```text
id                     UUID，canonical client identity
name                   唯一显示名称
status                 active | disabled
metadata               JSON map，不允许保存 secret
inserted_at
updated_at
```

`name` 可以修改；证书 SAN 中的 UUID 不变。

### 8.3 现有 `certificates` 扩展

新增 certificate type：

```text
client_auth_ca
client_auth_client
```

新增 nullable FK：

```text
client_auth_authority_id
client_auth_identity_id
```

对于 `client_auth_client`，两个 FK 均为必填。

保存内容：

- exact certificate PEM；
- canonical DER fingerprint；
- serial；
- issuer、subject；
- validity；
- revoked state 与 reason；
- 固定 profile metadata；
- CSR SHA-256，仅用于审计与幂等，不保存 private key。

### 8.4 `client_auth_issuance_requests`

用于 retry-safe issuance。

```text
request_id             UUID，unique
identity_id            FK
csr_sha256             32-byte digest
requested_ttl_seconds  integer
certificate_id         FK
inserted_at
```

语义：

- 相同 `request_id` 与相同规范化输入，返回原证书；
- 相同 `request_id` 但 CSR、identity 或 TTL 不同，返回 `idempotency_conflict`；
- 失败事务不消费 request ID。

### 8.5 `client_auth_crls`

```text
id                     UUID
authority_id           FK
issuer_certificate_id  FK
crl_number             bigint
generation             bigint
crl_pem                 text
crl_der_sha256          lowercase 64-char DER SHA-256
this_update             UTC datetime
next_update             UTC datetime
revoked_count           integer
inserted_at
```

约束：

```text
unique(authority_id, crl_number)
unique(authority_id, generation)
next_update > this_update
```

CRL record 创建后不可修改。

### 8.6 `client_auth_bundle_receipts`

用于观察 Agent convergence，不作为 PKI 正确性的前置条件。

```text
agent_id                Agent ID
client_auth_authority_id FK
generation              bigint
crl_number              bigint
bundle_sha256           lowercase 64-char hash
status                  applied | failed
last_error_code         nullable string
last_error_detail       nullable string
applied_at              nullable UTC datetime
updated_at
```

首版每个 Agent 只保存当前 receipt 即可。

---

## 9. Core 组件设计

### 9.1 `SecretHub.Core.PKI.ClientAuth`

公开 Context，负责授权、事务、审计和子模块协调。

建议 API：

```text
initialize_authority/2
status/0
create_identity/2
list_identities/1
get_identity/1
disable_identity/2
issue_certificate/4
list_certificates/1
get_certificate/1
revoke_certificate/3
refresh_crl/1
current_bundle/0
record_bundle_receipt/2
```

### 9.2 `ClientAuth.Authority`

职责：

- 初始化 singleton authority；
- 生成并加密保存 CA private key；
- 生成 self-signed CA certificate；
- 生成首个 empty CRL；
- 所有状态持久化成功后才切换为 `active`；
- 向 signer 提供经过验证的 active CA record 与解密 key。

以下情况必须 fail closed：

- Vault sealed；
- `SealState` process 不存在；
- CA key 无法解密；
- CA record revoked、expired、malformed 或不是 CA；
- key usage 不包含 `keyCertSign` 与 `cRLSign`。

生产环境不得在 `SealState` 缺失时使用固定 development fallback key。

### 9.3 `ClientAuth.Issuer`

签发流程：

1. 使用 `SecretHub.Core.PKI.CSR.parse/1` 解析 CSR。
2. 验证 CSR signature。
3. 验证 public-key algorithm 和强度。
4. 忽略 CSR subject 与 extension request。
5. 生成 canonical Client Authentication certificate。
6. 将有效期限制在 CA 有效期内。
7. 在保存前验证新证书确由指定 CA 签发。
8. 在一个事务中保存 certificate 与 idempotency evidence。
9. 写入 audit 与 PKI event。

该模块不得调用旧的 generic `CA.sign_csr/4`。

### 9.4 `ClientAuth.CRLManager`

建议接口：

```text
generate_locked/2
current/0
refresh_if_needed/1
validate_persisted_crl/2
```

默认策略：

```text
periodic check:          每 6 小时，加 jitter
CRL validity:            48 小时
refresh-ahead threshold: 12 小时
immediate refresh:       每次成功吊销后
```

CRL 生成算法：

1. `FOR UPDATE` 锁定 authority row。
2. 读取 current CRL number 与 generation。
3. 查询该 authority 所有 revoked 且尚未过期的 `client_auth_client` certificate。
4. 生成带 revocation time 与 reason 的 CRL entry。
5. CRL number 和 generation 各加一。
6. 使用 CA key 签名完整 CRL。
7. 保存前验证 issuer 与 signature。
8. 插入 immutable CRL row。
9. 更新 authority current pointers。
10. commit。
11. commit 后发布 trust-bundle changed event。

吊销与 CRL 发布在产品语义上必须是原子操作。如果 CRL 生成、验证或保存失败，证书吊销事务也失败，不能出现“数据库显示 revoked，但 Caddy 尚无对应 CRL”的状态。

已自然过期的 revoked certificate 可以从后续 CRL 中移除。

Reason mapping：

```text
key_compromise          -> keyCompromise
superseded              -> superseded
cessation_of_operation  -> cessationOfOperation
privilege_withdrawn     -> privilegeWithdrawn
operator_revoked        -> 不写 reason extension
```

### 9.5 `ClientAuth.TrustBundle`

生成 deterministic public bundle：

```json
{
  "schema_version": 1,
  "authority": "client-auth",
  "generation": 42,
  "ca_fingerprint": "...",
  "crl_number": 18,
  "crl_der_sha256": "...",
  "this_update": "2026-08-29T00:00:00Z",
  "next_update": "2026-08-31T00:00:00Z",
  "ca_bundle_pem": "-----BEGIN CERTIFICATE-----...",
  "crl_pem": "-----BEGIN X509 CRL-----...",
  "bundle_sha256": "..."
}
```

`bundle_sha256` 基于一个确定性的 binary transcript 计算，不包含 `bundle_sha256` 字段自身。

Bundle 是公开数据，只依赖数据库读取。因此即使 Vault sealed，也必须允许 Agent 拉取 current bundle。

### 9.6 `ClientAuth.Notifier`

新 generation commit 后：

1. 通过 Phoenix PubSub 向 SecretHub cluster 广播内部 event。
2. 每个 Core node 枚举本节点已连接 Agent。
3. 向具备 capability 的 Agent 发送：

```text
pki:client_auth_bundle:updated
```

Push 只携带 generation metadata，Agent 再主动 pull 完整 bundle。

当前 `ConnectionManager.send_to_agent/2` 发送的是 process message，因此必须在 `AgentRuntimeChannel` 增加 bridge：

```text
{:secrethub_agent_message, {:push, event, payload}}
  -> push(socket, event, payload)
```

Push 只是加速机制。Agent reconnect 与周期 reconciliation 才是最终一致性的保证。

---

## 10. Agent Runtime Protocol

所有消息都复用现有 mTLS-authenticated `agent:runtime` channel。

### 10.1 Capability

本机启用 Caddy trust bundle 功能后，`agent:hello` 增加：

```json
{
  "capabilities": {
    "client_auth_trust_bundle": {
      "schema_versions": [1],
      "consumer": "caddy"
    }
  }
}
```

CA 与 CRL 都是公开材料，因此任意当前已授权 Agent 均可读取；capability 和 receipt 主要用于控制本机行为和运维观测。

### 10.2 拉取当前 bundle

Event：

```text
pki:client_auth_bundle:get
```

Request：

```json
{
  "current_generation": 41,
  "current_bundle_sha256": "optional-current-hash"
}
```

未变化：

```json
{
  "status": "not_modified",
  "generation": 41
}
```

有更新：

```json
{
  "status": "updated",
  "bundle": {
    "schema_version": 1,
    "authority": "client-auth",
    "generation": 42,
    "ca_fingerprint": "...",
    "crl_number": 18,
    "crl_der_sha256": "...",
    "this_update": "...",
    "next_update": "...",
    "ca_bundle_pem": "...",
    "crl_pem": "...",
    "bundle_sha256": "..."
  }
}
```

### 10.3 更新通知

Core push：

```text
pki:client_auth_bundle:updated
```

Payload：

```json
{
  "generation": 42,
  "crl_number": 18,
  "reason": "certificate_revoked"
}
```

Agent 不能把通知本身视为 artifact，只将其作为 pull trigger。

### 10.4 安装 ACK

Event：

```text
pki:client_auth_bundle:ack
```

Payload：

```json
{
  "generation": 42,
  "crl_number": 18,
  "bundle_sha256": "...",
  "installed_at": "2026-08-29T00:00:10Z"
}
```

### 10.5 安装失败报告

Event：

```text
pki:client_auth_bundle:error
```

Payload：

```json
{
  "generation": 42,
  "code": "invalid_crl_signature",
  "detail": "redacted diagnostic text"
}
```

错误内容不得包含 private key、token、secret 或完整内部 stack trace。

---

## 11. SecretHub Agent 设计

### 11.1 Supervision

在可信 runtime connection 建立后启动：

```text
SecretHub.Agent.PKI.TrustBundleManager
```

建议 state：

```text
enabled
connection
storage_dir
current_generation
current_crl_number
current_bundle_sha256
next_update
sync_timer
retry_state
```

### 11.2 Reconciliation trigger

Agent 在以下时机请求 current bundle：

- runtime channel join 成功后；
- 收到 `pki:client_auth_bundle:updated`；
- 每 15 分钟周期检查，加 jitter；
- 本地 state validation 失败后；
- operator 执行本机 sync command 后。

### 11.3 本地验证

安装前必须验证：

1. manifest schema version 受支持；
2. deterministic bundle hash 正确；
3. CA PEM 可解析，首版恰好包含一个 CA；
4. CA self-signed 且签名有效；
5. CA 具有 `CA:TRUE`、`keyCertSign`、`cRLSign`；
6. CA canonical fingerprint 与 manifest 一致；
7. CRL PEM 可解析；
8. CRL issuer 与 CA 一致；
9. CRL signature 对该 CA 有效；
10. CRL number 与 manifest 一致；
11. CRL DER fingerprint 与 manifest 一致；
12. `thisUpdate` 不得超过当前时间五分钟以上；
13. `nextUpdate > now`；
14. generation 必须大于本地 generation，或同 generation 且 hash 完全相同；
15. CRL number 不得下降；
16. 相同 generation 不得出现不同 bytes。

### 11.4 原子本地存储

默认路径：

```text
/var/lib/secrethub/pki/client-auth/
├── watermark.json
├── generations/
│   ├── 00000000000000000041/
│   │   ├── ca.crt
│   │   ├── crl.pem
│   │   └── manifest.json
│   └── 00000000000000000042/
│       ├── ca.crt
│       ├── crl.pem
│       └── manifest.json
└── current -> generations/00000000000000000042
```

安装顺序：

```text
1. 校验 directory 与 symlink 安全性（拒绝 symlink traversal）
2. 创建 generation temp directory (mode 0750)
3. 使用 O_EXCL (exclusive write) 写入每个文件 (mode 0640)
4. fsync 文件
5. fsync temp directory
6. rename temp directory 为 final generation directory
7. 原子更新 watermark.json (tmp + rename + fsync)
8. 原子替换 current symlink
9. fsync base directory
10. 向 Core 提交 applied receipt ACK
```

建议权限：

```text
directory: 0750，owner secrethub，group caddy
file:      0644，owner secrethub，group caddy
```

虽然文件都是公开材料，但只有 Agent 具有写权限。

### 11.5 Last-known-good

收到无效 bundle 时：

- 拒绝新 bundle；
- 保留 current generation；
- 向 Core 报告 error；
- 按 backoff 重试；
- 不得用 invalid 或 older state 替换有效 bundle。

Core 不可用时，在 current CRL 未过期之前继续使用 last-known-good。

首次启动没有本地 bundle 且无法连接 Core 时，Agent 处于 PKI not-ready；Caddy protected listener 不得启动。

### 11.6 Readiness

通过 Agent 的现有操作接口暴露状态，也可生成：

```text
/run/secrethub/pki/client-auth.ready
```

Ready 条件：

- CA 文件有效；
- CRL 签名有效且未过期；
- current generation 原子可读；
- manifest 可验证。

---

## 12. Caddy 集成

### 12.1 Companion module

新增一个小型 Go companion repository：

```text
caddy-secrethub-pki
```

Caddy module ID：

```text
tls.client_auth.verifier.secrethub_client_auth
```

实现 Caddy `ClientCertificateVerifier`：

```go
VerifyClientCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error
```

该模块只访问本地文件，不连接 SecretHub。

### 12.2 Caddyfile

```caddyfile
service.example.net {
    tls {
        client_auth {
            mode require_and_verify

            trust_pool file \
                /var/lib/secrethub/pki/client-auth/current/ca.crt

            verifier secrethub_client_auth {
                bundle_dir /var/lib/secrethub/pki/client-auth/current
                ca_file /var/lib/secrethub/pki/client-auth/current/ca.crt
                crl_file /var/lib/secrethub/pki/client-auth/current/crl.pem
                manifest_file /var/lib/secrethub/pki/client-auth/current/manifest.json
                watermark_file /var/lib/secrethub/pki/client-auth/watermark.json
                expected_ca_fingerprint "8792bc0fa20e137b26ac4467d91c67926b86edee0352534a5b71f6fd8aa724b5"
                reload_interval 5s
                clock_skew 5m
            }
        }
    }

    reverse_proxy 127.0.0.1:8080
}
```

最终语法可以按 Caddy module convention 调整，但语义固定。

### 12.3 Verifier 行为

Provision 阶段：

- CA 和 CRL 文件必须存在；
- 两者必须可解析；
- CRL issuer 与 signature 必须验证；
- CRL 必须处于有效时间窗口；
- 任一失败则 Caddy 配置加载失败。

Runtime：

- 按配置 interval 检查 CRL file 或 `current` symlink；
- 新 CRL 通过完整验证后才原子替换内存 state；
- 新文件无效时继续使用旧的 valid CRL；
- 旧 CRL 到达 `nextUpdate` 后，所有新 client handshake fail closed；
- 解析 `rawCerts[0]` 作为 leaf；
- 要求至少一个 `verifiedChains`；
- 要求 leaf `CA:FALSE`；
- 要求 EKU 包含 `clientAuth`；
- 要求只有一个 `urn:secrethub:client:` URI SAN；
- 将 CRL 与 verified issuer 匹配；
- leaf serial 出现在 CRL 时拒绝。

Revocation index 使用：

```text
issuer identity + serial
```

不得只使用 serial，避免不同 CA serial collision。

### 12.4 CA 更新

首版 CA 不可变，正常运行不需要 Caddy reload。只有 CRL 更新，由 verifier 自己 hot reload。

未来 CA rotation 可以增加 overlap bundle 与明确 Caddy reload orchestration，但不属于本设计首版。

### 12.5 已有连接

CRL 在 TLS handshake 时生效，因此：

- 新连接会被拒绝；
- 已建立 HTTP/2、HTTP/3 或 WebSocket 不会自动断开。

需要立即断开的业务必须在 upstream application 或 connection manager 层另行实现。

---

## 13. Admin API

所有 mutation endpoint 必须使用现有 SecretHub administrator authorization，不能放入仅 token-authenticated 的普通 read pipeline。

建议路由：

```text
POST /v1/pki/client-auth/initialize
GET  /v1/pki/client-auth/status

POST /v1/pki/client-auth/identities
GET  /v1/pki/client-auth/identities
GET  /v1/pki/client-auth/identities/:id
POST /v1/pki/client-auth/identities/:id/disable

POST /v1/pki/client-auth/identities/:id/certificates
GET  /v1/pki/client-auth/identities/:id/certificates
GET  /v1/pki/client-auth/certificates/:id
POST /v1/pki/client-auth/certificates/:id/revoke

POST /v1/pki/client-auth/crl/refresh
GET  /v1/pki/client-auth/crl
GET  /v1/pki/client-auth/bundle
GET  /v1/pki/client-auth/agents
```

### 13.1 初始化

Request：

```json
{
  "name": "SecretHub Client Authentication CA",
  "key_algorithm": "ecdsa_p384",
  "ca_validity_days": 1825,
  "default_ttl_seconds": 2592000,
  "max_ttl_seconds": 7776000
}
```

Response 只包含公开数据：

```json
{
  "authority_id": "...",
  "status": "active",
  "ca_certificate_pem": "...",
  "ca_fingerprint": "...",
  "generation": 1,
  "crl_number": 1,
  "next_update": "..."
}
```

不得出现 private key。

### 13.2 创建 identity

```json
{
  "name": "backup-agent-amsterdam",
  "metadata": {
    "owner": "infrastructure",
    "purpose": "backup"
  }
}
```

### 13.3 签发证书

```json
{
  "request_id": "UUID",
  "csr": "-----BEGIN CERTIFICATE REQUEST-----...",
  "ttl_seconds": 2592000
}
```

Response：

```json
{
  "certificate_id": "...",
  "certificate_pem": "...",
  "ca_bundle_pem": "...",
  "serial_number": "...",
  "canonical_fingerprint": "...",
  "identity_uri": "urn:secrethub:client:...",
  "valid_from": "...",
  "valid_until": "..."
}
```

### 13.4 吊销证书

```json
{
  "reason": "key_compromise"
}
```

只有新 CRL 已持久化后才返回成功：

```json
{
  "certificate_id": "...",
  "revoked": true,
  "revoked_at": "...",
  "crl_number": 19,
  "bundle_generation": 43
}
```

---

## 14. Admin UI

在现有 PKI 管理区新增独立的 **Client Authentication** 页面。

### Overview

显示：

- authority status；
- CA subject、canonical fingerprint、有效期；
- current CRL number；
- CRL `thisUpdate` / `nextUpdate`；
- bundle generation；
- active identity 与 certificate 数量；
- Agent convergence 状态。

### Identities

支持：

- 创建 identity；
- 查看 active/disabled identity；
- 查看该 identity 的全部证书；
- 粘贴或上传 CSR 并签发；
- disable identity 并吊销全部活动证书。

### Certificates

显示：

- subject、SAN、serial、canonical fingerprint；
- validity 与 status；
- 下载公开 certificate；
- 选择 controlled reason 吊销。

### Distribution

显示：

- Agent name 与 ID；
- 是否报告 capability；
- applied generation；
- desired generation；
- last applied time；
- current error code。

UI 不得提供 CA private-key download、copy 或 reveal 功能。

---

## 15. Cluster 与一致性

SecretHub Core 可能是多节点部署。正确性不能依赖单节点 GenServer。

使用 PostgreSQL transaction 与 row lock 保护：

- authority initialization；
- serial uniqueness；
- issuance idempotency；
- certificate revocation；
- CRL number increment；
- bundle generation increment。

CRL refresh worker 可在所有 Core node 上运行。只有成功锁定 authority row 且确认需要 refresh 的 worker 才生成下一版 CRL。

Commit 后通过 Phoenix PubSub 将 bundle-changed event 发送至所有 Core node，每个 node 只通知自己本地连接的 Agent。

Notification 失败不回滚已生成的 CRL。Agent reconnect 与 periodic reconciliation 会最终同步。

---

## 16. Seal State 语义

需要 CA private key 的操作要求 Vault unsealed：

```text
authority initialization
certificate issuance
certificate revocation
disable identity 且存在 active certificate
CRL refresh
```

以下公开操作在 sealed 时仍可用：

```text
读取 authority status
读取 certificate metadata
读取 current CA bundle
读取 current CRL
Agent trust-bundle synchronization
```

`SealState` 缺失或 sealed 时，private-key operation 使用稳定错误码 fail closed。生产环境不得生成或使用固定 test fallback key。

---

## 17. Failure Semantics

| 故障 | 必须行为 |
|---|---|
| Core 不可用 | Agent 和 Caddy 继续使用 last-known-good，直到 CRL 过期 |
| Core sealed | 公开 bundle sync 继续；签发和 CRL 变更停止 |
| Agent 断线 | Caddy 继续使用当前本地 bundle |
| 新 bundle 无效 | Agent 拒绝并保留 current generation |
| Bundle rollback | Agent 拒绝 |
| Update push 丢失 | Agent periodic reconciliation 修复 |
| ACK 丢失 | Core 状态显示可能滞后，但 PKI 正确性不受影响 |
| CRL 过期 | Caddy 拒绝新的 client handshake |
| Caddy 启动时 CA 缺失 | 配置加载失败 |
| Caddy 启动时 CRL 缺失 | 配置加载失败 |
| Caddy 发现新 CRL 无效 | 保留旧 valid CRL；旧 CRL 过期后 fail closed |
| 已建立连接使用 revoked cert | 已有连接继续；新的 handshake 失败 |

---

## 18. 安全要求

以下均为 release blocker：

1. 修复 `SealState` 缺失时使用固定 development PKI encryption key 的生产 fail-open 行为。
2. Controller、LiveView、日志、telemetry、Agent message 均不得暴露 CA private key。
3. Client Authentication issuer 不得使用 generic `CA.sign_csr/4`。
4. 提取 public key 前必须验证 CSR signature。
5. Subject、SAN、EKU 和 TTL 必须由服务端控制。
6. 新授权只能使用 canonical DER SHA-256 fingerprint。
7. 每次签发前验证 CA key usage、validity、self-signature 与 profile。
8. Leaf validity 不得超过 CA validity。
9. Revocation 与 CRL publication 必须原子完成。
10. CRL number 与 bundle generation 必须单调递增。
11. Agent 拒绝 stale、rollback 或相同 generation 不同内容。
12. Caddy 对缺失、invalid、expired revocation state fail closed。
13. Upstream 不得信任客户端自行发送的身份 HTTP header。
14. Agent 的所有 public-material write 必须原子且防 symlink attack。
15. 创建 generation directory 时不得跟随攻击者控制的 symlink。

---

## 19. Audit 与 Telemetry

必要 audit event：

```text
pki.client_auth.authority_initialized
pki.client_auth.identity_created
pki.client_auth.identity_disabled
pki.client_auth.certificate_issued
pki.client_auth.certificate_revoked
pki.client_auth.crl_published
pki.client_auth.bundle_agent_applied
pki.client_auth.bundle_agent_failed
```

Event 应包含相关 ID、serial、canonical fingerprint、request/correlation ID、generation、CRL number、actor 与 result code。不得保存 private key 或完整 CSR body。

建议 telemetry event：

```text
[:secrethub, :pki, :client_auth, :issue]
[:secrethub, :pki, :client_auth, :revoke]
[:secrethub, :pki, :client_auth, :crl, :generate]
[:secrethub, :agent, :pki, :bundle, :sync]
[:secrethub, :agent, :pki, :bundle, :install]
```

建议 measurement：

- duration；
- result；
- certificate count；
- revoked count；
- CRL bytes；
- generation lag；
- 从 revocation commit 到 Agent ACK 的时间。

---

## 20. 部署与启动顺序

### 首次部署

1. 部署 Core migration 与新代码。
2. Unseal SecretHub。
3. 初始化 Client Authentication CA 与 empty CRL。
4. 在 Caddy 主机部署启用 `TrustBundleManager` 的 Agent。
5. 等待 Agent 同步 generation 1。
6. 验证本地 CA、CRL 与 manifest。
7. 安装包含 `caddy-secrethub-pki` 的 custom Caddy build。
8. 配置 Caddy 使用 Agent-managed files。
9. 启动 Caddy。
10. 为每个客户端签发新的 SecretHub certificate。
11. 将新 certificate 与本地 private key 配对安装到客户端。
12. 执行 clean cutover 并停止 `client-ca`。

### Boot ordering

首次安装时，Agent 尚未写入 valid bundle 前，Caddy protected listener 不得启动。

NixOS/systemd 可采用：

```text
Caddy ExecStartPre bundle validation
Caddy After/Requires Agent PKI readiness unit
Caddy restart-on-failure，直到 trust files 出现
```

第一次成功同步后，持久化 last-known-good 可以支持离线重启，前提是 CRL 未过期。

---

## 21. 从 `client-ca` Clean Cutover

不实现产品级 migration 或 compatibility layer。

切换步骤：

```text
初始化 SecretHub Client Authentication CA
为每个客户端签发 replacement certificate
在客户端安装 replacement certificate
确认 Caddy host 上 Agent 已同步 trust bundle
将 Caddy trust 配置切换到 SecretHub files
验证允许与拒绝的 handshake
吊销测试证书并验证 CRL propagation
停止并移除 client-ca runtime service
按 operator policy 归档或销毁旧 client-ca secret material
```

切换边界之后：

- 旧 `client-ca` 签发证书不再被接受；
- SecretHub 签发证书开始被接受；
- 产品不要求 dual-trust period；
- 不导入旧证书记录。

---

## 22. 测试策略

### Core unit test

- CA certificate profile；
- CA private key encrypted at rest；
- API response 不含 private key；
- sealed 或缺失 `SealState` 时 fail closed；
- valid CSR accepted；
- malformed CSR rejected；
- tampered CSR signature rejected；
- RSA < 2048 rejected；
- unsupported EC curve rejected；
- CSR subject/SAN 被忽略；
- issued certificate 只有 canonical profile；
- certificate 可由 CA 验证；
- leaf expiry bounded by CA expiry；
- issuance replay 与 conflict；
- canonical DER fingerprint。

### CRL test

- initial empty CRL valid；
- CRL number 单调；
- generation 单调；
- revoked serial 恰好出现一次；
- reason mapping；
- expired revoked certificate 从后续 CRL 移除；
- CRL issuer 与 signature 有效；
- concurrent revocation 正确序列化；
- CRL generation failure 时 revocation rollback；
- `nextUpdate` 前 scheduled refresh。

### Agent test

- initial install；
- not_modified；
- push-triggered sync；
- reconnect sync；
- invalid CA rejection；
- invalid CRL signature rejection；
- expired CRL rejection；
- generation rollback rejection；
- same generation/different hash rejection；
- atomic current switch；
- write crash 保留旧 generation；
- ACK 与 error reporting。

### Caddy module test

- valid client accepted；
- no client certificate rejected；
- untrusted CA rejected；
- revoked certificate rejected；
- expired CRL rejected；
- malformed CRL rejected；
- wrong issuer rejected；
- invalid signature rejected；
- missing `clientAuth` rejected；
- `CA:TRUE` leaf rejected；
- invalid identity SAN rejected；
- valid CRL hot replacement 无需 Caddy reload 即生效；
- invalid replacement 保留旧 CRL；
- 旧 CRL 过期后 fail closed。

### E2E

真实启动 Core、Agent、custom Caddy 和 TLS client：

```text
初始化 CA
创建 identity
客户端本地生成 key 和 CSR
签发 certificate
通过 Caddy 成功连接
吊销 certificate
等待 Agent ACK 新 generation
验证新 handshake 被拒绝
重启 Core 与 Agent
验证 last-known-good 恢复
```

OpenSSL 还必须独立验证 certificate 与 CRL。

---

## 23. 建议代码结构

### SecretHub Core

```text
apps/secrethub_core/lib/secrethub_core/pki/client_auth.ex
apps/secrethub_core/lib/secrethub_core/pki/client_auth/authority.ex
apps/secrethub_core/lib/secrethub_core/pki/client_auth/identity.ex
apps/secrethub_core/lib/secrethub_core/pki/client_auth/issuer.ex
apps/secrethub_core/lib/secrethub_core/pki/client_auth/crl_manager.ex
apps/secrethub_core/lib/secrethub_core/pki/client_auth/trust_bundle.ex
apps/secrethub_core/lib/secrethub_core/pki/client_auth/notifier.ex
apps/secrethub_core/lib/secrethub_core/workers/client_auth_crl_refresher.ex
```

### Shared schemas

```text
client_auth_authority.ex
client_auth_identity.ex
client_auth_issuance_request.ex
client_auth_crl.ex
client_auth_bundle_receipt.ex
certificate.ex additions
```

### SecretHub Web

```text
pki_client_auth_controller.ex
client_auth_live.ex
router.ex additions
agent_runtime_channel.ex additions
```

### SecretHub Agent

```text
pki/trust_bundle_manager.ex
pki/bundle_validator.ex
pki/atomic_store.ex
connection.ex additions
application.ex supervision additions
```

### Companion Caddy repository

```text
caddy-secrethub-pki/
├── module.go
├── verifier.go
├── loader.go
├── caddyfile.go
└── verifier_test.go
```

---

## 24. 实施顺序

### Phase 0 — Security prerequisite

- 修复生产 fallback encryption key；
- 移除 CA private-key API response；
- 将 canonical fingerprint 设为新授权唯一格式。

### Phase 1 — Core authority 与 issuance

- migration 与 schema；
- authority initialization；
- identity management；
- canonical CSR issuance；
- Admin API 与基础 UI。

### Phase 2 — Revocation 与 CRL

- CRL manager；
- atomic revocation；
- periodic refresh；
- trust-bundle construction。

### Phase 3 — Agent distribution

- Channel request/reply；
- Core push bridge；
- Agent validation、atomic storage、ACK。

### Phase 4 — Caddy enforcement

- custom verifier；
- Caddy integration test；
- NixOS/custom Caddy package。

### Phase 5 — E2E 与 cutover

- production-like E2E；
- 为客户端签发 replacement certificate；
- 切换 Caddy；
- 下线 `client-ca`。

---

## 25. 最终设计约束

实现必须始终满足：

```text
SecretHub Core 是 Client CA signing capability 的唯一持有者。
Client private key 始终保留在客户端。
SecretHub Agent 只保存公开 CA 和 CRL。
Caddy 不持有 SecretHub credential，也不执行在线 PKI lookup。
Revocation 只有在新签名 CRL 持久化后才返回成功。
Agent bundle update 必须经过认证、验证、反回滚并原子安装。
Caddy 对 missing、invalid、stale 或 revoked trust state fail closed。
旧 client-ca 不被导入或模拟。
S3 不属于运行时架构。
```
