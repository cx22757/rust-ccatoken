# CCA Token 格式说明

根据 `src/token/evidence.rs` 的代码分析，CCA Token 的格式结构如下：

## 1. 整体结构（CBOR 编码）

```
CBOR Tag(399) {
  44234: <Platform Token>   // 平台令牌
  44241: <Realm Token>      // 领域令牌
}
```

- **CBOR Tag**: `399` (第27行)
- **Platform Label**: `44234` (第28行)
- **Realm Label**: `44241` (第29行)

## 2. Evidence 结构体

```rust
pub struct Evidence {
    pub platform_claims: Platform,      // 解码后的平台声明集
    pub realm_claims: Realm,            // 解码后的领域声明集
    pub platform: CoseMessage,          // 平台的 COSE Sign1 信封
    pub realm: CoseMessage,             // 领域的 COSE Sign1 信封
    platform_tvec: TrustVector,         // 平台 AR4SI 信任向量
    realm_tvec: TrustVector,            // 领域 AR4SI 信任向量
}
```

## 3. Platform Claims 字段

| 字段 | 说明 |
|------|------|
| `profile` | 配置文件标识符 |
| `challenge` | 挑战值（用于绑定RAK） |
| `impl_id` | 实现ID |
| `inst_id` | 实例ID |
| `config` | 配置值 |
| `lifecycle` | 生命周期状态 |
| `verification_service` | 可选的验证服务URL |
| `hash_alg` | 使用的哈希算法 (sha-256/sha-512) |
| `sw_components` | 软件组件列表 |

每个 `sw_component` 包含：
- `mtyp`: 测量类型
- `version`: 版本
- `hash_alg`: 哈希算法
- `mval`: 测量值
- `signer_id`: 签名者ID

## 4. Realm Claims 字段

| 字段 | 说明 |
|------|------|
| `profile` | 配置文件标识符（空=legacy） |
| `challenge` | 挑战值 |
| `perso` | 个性化值 |
| `rim` | 领域初始测量哈希 |
| `rem` | 领域扩展测量列表 |
| `hash_alg` | 哈希算法 |
| `rak_hash_alg` | RAK哈希算法 (sha-256/sha-512) |
| `cose_rak` | COSE格式的领域认证密钥（新格式） |
| `raw_rak` | 原始格式的RAK（legacy格式） |

## 5. 密码学绑定机制

平台令牌和领域令牌通过以下方式绑定：

1. 平台的 `challenge` 字段 = RAK (Realm Attestation Key) 的哈希值
2. 验证时检查 `hash(RAK) == platform.challenge`

## 6. 验证流程

```
┌─────────────────────────────────────────────────────────┐
│  1. 验证 Platform Token（使用 CPAK）                     │
│  └── 失败则终止，无法继续验证 Realm                       │
├─────────────────────────────────────────────────────────┤
│  2. 验证 Realm Token（使用 RAK）                         │
├─────────────────────────────────────────────────────────┤
│  3. 检查 Binding: hash(RAK) == platform.challenge       │
└─────────────────────────────────────────────────────────┘
```


## 7. Mock CCA SDK .so 接口

根据 `testdata/generate_cbor/mock_cca_sdk.c`，Mock SDK 导出两个接口：

### API 1: `get_attestation_token`

获取 CCA attestation token。

```c
int get_attestation_token(
    unsigned char *challenge,  // [in]  挑战值（可选）
    size_t challenge_len,      // [in]  挑战值长度
    unsigned char *token,      // [out] Token 输出缓冲区
    size_t *token_len          // [in/out] Token 长度
);
```

**参数说明：**
- `challenge`: 挑战值指针，如果 `challenge_len > 0` 则必须非空
- `challenge_len`: 挑战值长度（字节）
- `token`: Token 输出缓冲区，`NULL` 时仅查询所需长度
- `token_len`: 输入时为缓冲区大小，输出时为实际 Token 长度

**使用方式：**
1. **查询长度**: 调用时 `token = NULL`，返回 `*token_len = 所需长度`
2. **获取数据**: 调用时提供足够大的缓冲区

**返回值：**
- `0`: 成功
- `1`: 失败（参数错误或缓冲区太小）

### API 2: `get_dev_cert`

获取设备证书（PEM 格式）。

```c
int get_dev_cert(
    unsigned char *dev_cert,  // [out] 证书输出缓冲区
    size_t *dev_cert_len      // [in/out] 证书长度
);
```

**参数说明：**
- `dev_cert`: 证书输出缓冲区，`NULL` 时仅查询所需长度
- `dev_cert_len`: 输入时为缓冲区大小，输出时为实际证书长度（含 NULL 终止符）

**使用方式：**
1. **查询长度**: 调用时 `dev_cert = NULL`，返回 `*dev_cert_len = 所需长度`
2. **获取数据**: 调用时提供足够大的缓冲区

**返回值：**
- `0`: 成功
- `1`: 失败（参数错误或缓冲区太小）

### Rust FFI 声明

```rust
#[link(name = "mock_cca_sdk")]
extern "C" {
    pub fn get_attestation_token(
        challenge: *mut c_uchar,
        challenge_len: usize,
        token: *mut c_uchar,
        token_len: *mut usize,
    ) -> c_int;

    pub fn get_dev_cert(
        dev_cert: *mut c_uchar,
        dev_cert_len: *mut usize,
    ) -> c_int;
}
```
