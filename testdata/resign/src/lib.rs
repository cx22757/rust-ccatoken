// src/lib.rs

mod constants;
// mod token;
mod token;

use constants::PLATFORM_CERT_PEM;
use token::TokenGenerator;
use std::ptr;
use std::slice;

/// 获取 CCA attestation token
///
/// # 参数
/// - `challenge`: 挑战值指针 (可选)
/// - `challenge_len`: 挑战值长度
/// - `token`: Token 输出缓冲区 (NULL 时仅查询长度)
/// - `token_len`: [in/out] 缓冲区大小 / 实际 Token 长度
///
/// # 返回值
/// - 0: 成功
/// - 1: 失败
#[no_mangle]
pub extern "C" fn get_attestation_token(
    challenge: *const u8,
    challenge_len: usize,
    token: *mut u8,
    token_len: *mut usize,
) -> i32 {
    // 参数验证
    if token_len.is_null() {
        return 1;
    }

    // 如果提供了 challenge_len，则 challenge 必须非空
    if challenge_len > 0 && challenge.is_null() {
        return 1;
    }

    if challenge_len > 64 {
        return 1;
    }

    let mut challenge_data = [0u8; 64];
    let input_slice = unsafe { slice::from_raw_parts(challenge, challenge_len) };
    // 拷贝数据到 challenge_data 的起始位置，剩余位保持为 0
    challenge_data[..challenge_len].copy_from_slice(&input_slice[..challenge_len]);

    // 生成 token
    let generator = match TokenGenerator::new() {
        Ok(g) => g,
        Err(_) => return 1,
    };

    let token_data = match generator.generate_token(&challenge_data) {
        Ok(t) => t,
        Err(_) => return 1,
    };

    // 如果 token 为 NULL，仅返回所需长度
    if token.is_null() {
        unsafe {
            *token_len = token_data.len();
        }
        return 0;
    }

    // 检查缓冲区大小
    let buffer_size = unsafe { *token_len };
    if buffer_size < token_data.len() {
        unsafe {
            *token_len = token_data.len();
        }
        return 1;
    }

    // 复制数据到输出缓冲区
    unsafe {
        ptr::copy_nonoverlapping(token_data.as_ptr(), token, token_data.len());
        *token_len = token_data.len();
    }

    0
}

/// 获取设备证书 (PEM 格式)
///
/// # 参数
/// - `dev_cert`: 证书输出缓冲区 (NULL 时仅查询长度)
/// - `dev_cert_len`: [in/out] 缓冲区大小 / 实际证书长度
///
/// # 返回值
/// - 0: 成功
/// - 1: 失败
#[no_mangle]
pub extern "C" fn get_dev_cert(
    dev_cert: *mut u8,
    dev_cert_len: *mut usize,
) -> i32 {
    // 参数验证
    if dev_cert_len.is_null() {
        return 1;
    }

    let cert_bytes = PLATFORM_CERT_PEM.as_bytes();
    let cert_len = cert_bytes.len() + 1; // 包含 NULL 终止符

    // 如果 dev_cert 为 NULL，仅返回所需长度
    if dev_cert.is_null() {
        unsafe {
            *dev_cert_len = cert_len;
        }
        return 0;
    }

    // 检查缓冲区大小
    let buffer_size = unsafe { *dev_cert_len };
    if buffer_size < cert_len {
        unsafe {
            *dev_cert_len = cert_len;
        }
        return 1;
    }

    // 复制证书到输出缓冲区
    unsafe {
        ptr::copy_nonoverlapping(cert_bytes.as_ptr(), dev_cert, cert_bytes.len());
        // 添加 NULL 终止符
        *dev_cert.add(cert_bytes.len()) = 0;
        *dev_cert_len = cert_len;
    }

    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_attestation_token_query_length() {
        let mut token_len = 0;
        let result = get_attestation_token(ptr::null(), 0, ptr::null_mut(), &mut token_len);
        assert_eq!(result, 0);
        assert!(token_len > 0);
    }

    #[test]
    fn test_get_attestation_token_with_buffer() {
        let challenge = [0x42u8; 64];
        let mut token_len = 0;

        // 首先查询长度
        let result = get_attestation_token(
            challenge.as_ptr(),
            challenge.len(),
            ptr::null_mut(),
            &mut token_len,
        );
        assert_eq!(result, 0);

        // 分配缓冲区并获取 token
        let mut buffer_len = token_len + 1000;
        let mut buffer = vec![0u8; buffer_len];
        let result = get_attestation_token(
            challenge.as_ptr(),
            challenge.len(),
            buffer.as_mut_ptr(),
            &mut buffer_len,
        );
        assert_eq!(result, 0);
    }

    #[test]
    fn test_get_dev_cert_query_length() {
        let mut cert_len = 0;
        let result = get_dev_cert(ptr::null_mut(), &mut cert_len);
        assert_eq!(result, 0);
        assert!(cert_len > 0);
    }

    #[test]
    fn test_get_dev_cert_with_buffer() {
        let mut cert_len = 0;

        // 首先查询长度
        let result = get_dev_cert(ptr::null_mut(), &mut cert_len);
        assert_eq!(result, 0);

        // 分配缓冲区并获取证书
        let mut buffer = vec![0u8; cert_len];
        let result = get_dev_cert(buffer.as_mut_ptr(), &mut cert_len);
        assert_eq!(result, 0);

        // 验证是 NULL 终止的字符串
        assert_eq!(buffer[cert_len - 1], 0);
    }
}