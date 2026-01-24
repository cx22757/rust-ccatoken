#include <string.h>
#include <stddef.h>
#include <wchar.h>

#include "common.h" // 包含 MOCK_TOKEN_DATA, MOCK_CERT_PEM, device_cert

// =============================================================
// Exported API 1: get_attestation_token
// =============================================================
// Rust FFI:
// pub fn get_attestation_token(
//     challenge: *mut c_uchar, challenge_len: usize,
//     token: *mut c_uchar, token_len: *mut usize,
// ) -> c_int;
//
// Returns: 0 on success, 1 on error
int get_attestation_token(
    unsigned char *challenge,
    size_t challenge_len,
    unsigned char *token,
    size_t *token_len
)
{
    // 1. 如果 challenge_len 非 0，必须提供 challenge 指针
    if (challenge_len > 0 && challenge == NULL) {
        return 1;
    }

    // 2. 必须提供 token_len 指针用于返回数据长度
    if (token_len == NULL) {
        return 1;
    }

    // 3. 场景 A: 查询长度 (Token 为 NULL)
    if (token == NULL) {
        *token_len = MOCK_TOKEN_LEN;
        return 0; // Success
    }

    // 4. 场景 B: 获取数据 (Token 非 NULL)
    // 检查调用者提供的缓冲区是否足够大
    if (*token_len < MOCK_TOKEN_LEN) {
        return 1; // Error: Buffer too small
    }

    // 5. 执行内存拷贝
    memcpy(token, MOCK_TOKEN_DATA, MOCK_TOKEN_LEN);
    
    // 更新实际写入的长度
    *token_len = MOCK_TOKEN_LEN;
    
    return 0; // Success
}

// =============================================================
// Exported API 2: get_dev_cert
// =============================================================
// Rust FFI:
// pub fn get_dev_cert(
//     dev_cert: *mut c_uchar, dev_cert_len: *mut usize,
// ) -> wchar_t;
//
// Returns: 0 on success, 1 on error
int get_dev_cert(
    unsigned char *dev_cert,
    size_t *dev_cert_len
)
{
    const char *cert_pem = MOCK_CERT_PEM;
    // 计算所需长度（包含结尾的 NULL 终止符）
    size_t required_len = strlen(cert_pem) + 1;

    // 1. 必须提供 dev_cert_len 指针
    if (dev_cert_len == NULL) {
        return 1;
    }

    // 2. 场景 A: 查询长度 (dev_cert 为 NULL)
    if (dev_cert == NULL) {
        *dev_cert_len = required_len;
        return 0; // Success
    }

    // 3. 场景 B: 获取数据
    // 检查缓冲区大小
    if (*dev_cert_len < required_len) {
        return 1; // Error: Buffer too small
    }

    // 4. 执行内存拷贝
    memcpy(dev_cert, cert_pem, required_len);
    
    // 更新实际写入的长度
    *dev_cert_len = required_len;

    return 0; // Success
}