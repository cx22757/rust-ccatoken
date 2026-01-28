// src/token.rs

use crate::constants::*;
use ciborium::value::Integer;
use ciborium::Value;
use openssl::bn::BigNumContext;
use openssl::ec::{EcGroup, EcKey};
use openssl::ecdsa::EcdsaSig;
use openssl::hash::{hash, MessageDigest};
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::sign::Signer;

pub struct TokenGenerator {
    platform_key: PKey<Private>,
}

impl TokenGenerator {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        // 1. 专门解析 EC 格式的私钥 (处理 -----BEGIN EC PRIVATE KEY-----)
        let ec_key = EcKey::private_key_from_pem(PLATFORM_PRIV_KEY_PEM.as_bytes())?;
        // 2. 将 EcKey 转换为通用的 PKey 包装器
        let platform_key = PKey::from_ec_key(ec_key)?;
        Ok(Self { platform_key })
    }

    pub fn generate_token(&self, challenge: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        // 1. 解析模板 token
        let template_bytes = hex::decode(TEMPLATE_TOKEN_HEX.replace(['\n', ' '], ""))?;
        let mut token: Value = ciborium::from_reader(&template_bytes[..])?;

        // 2. 生成临时 P-521 密钥对 (Realm Attestation Key - RAK)
        let group = EcGroup::from_curve_name(Nid::SECP521R1)?;
        let rak_ec_key = EcKey::generate(&group)?;
        let rak_pkey = PKey::from_ec_key(rak_ec_key.clone())?;

        // 3. 提取 RAK 公钥 - 保持完整的 133 字节 (0x04 + x + y)
        let mut bn_ctx = BigNumContext::new()?;
        let rak_pub_bytes = rak_ec_key.public_key().to_bytes(
            &group,
            openssl::ec::PointConversionForm::UNCOMPRESSED,
            &mut bn_ctx,
        )?;

        // 验证是 133 字节的未压缩格式
        // if rak_pub_bytes.len() != 133 || rak_pub_bytes[0] != 0x04 {
        //     return Err("Invalid P-521 public key format".into());
        // }

        // 4. 计算 RAK 的 SHA-256 哈希 (用于绑定到 Platform Token)
        let rak_hash = hash(MessageDigest::sha256(), &rak_pub_bytes)?;

        // 5. 修改 token 结构
        if let Value::Tag(399, inner) = &mut token {
            if let Value::Map(root_map) = inner.as_mut() {
                // 修改 Platform Token (注入 RAK Hash)
                self.update_platform_token(root_map, &rak_hash)?;

                // 修改 Realm Token (注入 Challenge 和 RAK Key)
                self.update_realm_token(root_map, challenge, &rak_pub_bytes)?;

                // 对 Realm Token 进行签名 (使用 RAK 私钥)
                self.sign_token(root_map, REALM_LABEL, &rak_pkey)?;

                // 对 Platform Token 进行签名 (使用 Platform 私钥)
                self.sign_token(root_map, PLATFORM_LABEL, &self.platform_key)?;
            }
        }

        // 6. 序列化最终的 token
        let mut buffer = Vec::new();
        ciborium::into_writer(&token, &mut buffer)?;

        Ok(buffer)
    }

    /// 更新 Platform Token 的 Claims
    fn update_platform_token(
        &self,
        root_map: &mut Vec<(Value, Value)>,
        rak_hash: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        // 查找 Platform Token
        for (k, v) in root_map.iter_mut() {
            if Self::match_label(k, PLATFORM_LABEL) {
                // Platform Token 的值可能是 Value::Bytes，需要先反序列化
                let mut cose_sign1 = if let Value::Bytes(bytes) = v {
                    // 从字节反序列化为 COSE_Sign1 结构
                    ciborium::from_reader::<Value, _>(&bytes[..])?
                } else {
                    v.clone()
                };

                // 现在 cose_sign1 应该是 Tag(18, Array) 或 Array
                let cose_array = Self::extract_cose_array_from_value(&mut cose_sign1)?;

                // 更新签名算法
                self.update_token_header_alg(cose_array, COSE_ALG_ES512)?;

                if cose_array.len() >= 3 {
                    // cose_array[2] 是 payload
                    if let Value::Bytes(payload_bytes) = &mut cose_array[2] {
                        // 解析 payload 为 Claims Map
                        let mut claims: Value = ciborium::from_reader(&payload_bytes[..])?;

                        if let Value::Map(claims_map) = &mut claims {
                            // 更新 challenge 字段
                            for (ck, cv) in claims_map.iter_mut() {
                                if Self::match_label(ck, PLATFORM_CHALLENGE_LABEL) {
                                    *cv = Value::Bytes(rak_hash.to_vec());
                                    break;
                                }
                            }
                        }

                        // 重新序列化 claims
                        let mut new_payload = Vec::new();
                        ciborium::into_writer(&claims, &mut new_payload)?;
                        *payload_bytes = new_payload;
                    }
                }

                // 重新序列化回 Value::Bytes
                let mut new_bytes = Vec::new();
                ciborium::into_writer(&cose_sign1, &mut new_bytes)?;
                *v = Value::Bytes(new_bytes);

                break;
            }
        }
        Ok(())
    }

    /// 更新 Realm Token 的 Claims
    fn update_realm_token(
        &self,
        root_map: &mut Vec<(Value, Value)>,
        challenge: &[u8],
        rak_pub_bytes: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        // 查找 Realm Token
        for (k, v) in root_map.iter_mut() {
            if Self::match_label(k, REALM_LABEL) {
                // Realm Token 的值可能是 Value::Bytes，需要先反序列化
                let mut cose_sign1 = if let Value::Bytes(bytes) = v {
                    ciborium::from_reader::<Value, _>(&bytes[..])?
                } else {
                    v.clone()
                };

                // 提取 COSE_Sign1 数组
                let cose_array = Self::extract_cose_array_from_value(&mut cose_sign1)?;

                // 更新签名算法
                self.update_token_header_alg(cose_array, COSE_ALG_ES512)?;

                if cose_array.len() >= 3 {
                    // cose_array[2] 是 payload
                    if let Value::Bytes(payload_bytes) = &mut cose_array[2] {
                        // 解析 payload 为 Claims Map
                        let mut claims: Value = ciborium::from_reader(&payload_bytes[..])?;

                        if let Value::Map(claims_map) = &mut claims {
                            // 更新 challenge 和 RAK
                            for (ck, cv) in claims_map.iter_mut() {
                                if Self::match_label(ck, REALM_CHALLENGE_LABEL) {
                                    *cv = Value::Bytes(challenge.to_vec());
                                } else if Self::match_label(ck, REALM_RAK_LABEL) {
                                    *cv = Value::Bytes(rak_pub_bytes.to_vec());
                                }
                            }
                        }

                        // 重新序列化 claims
                        let mut new_payload = Vec::new();
                        ciborium::into_writer(&claims, &mut new_payload)?;
                        *payload_bytes = new_payload;
                    }
                }

                // 重新序列化回 Value::Bytes
                let mut new_bytes = Vec::new();
                ciborium::into_writer(&cose_sign1, &mut new_bytes)?;
                *v = Value::Bytes(new_bytes);

                break;
            }
        }
        Ok(())
    }

    /// 通用的签名函数
    fn sign_token(
        &self,
        root_map: &mut Vec<(Value, Value)>,
        token_label: i128,
        signing_key: &PKey<Private>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // 查找对应的 token
        for (k, v) in root_map.iter_mut() {
            if Self::match_label(k, token_label) {
                // Token 的值可能是 Value::Bytes，需要先反序列化
                let mut cose_sign1 = if let Value::Bytes(bytes) = v {
                    ciborium::from_reader::<Value, _>(&bytes[..])?
                } else {
                    v.clone()
                };

                // 提取 COSE_Sign1 数组
                let cose_array = Self::extract_cose_array_from_value(&mut cose_sign1)?;

                if cose_array.len() >= 4 {
                    // COSE_Sign1 结构: [protected, unprotected, payload, signature]

                    // 构造 Sig_structure
                    // Sig_structure = [
                    //     context: "Signature1",
                    //     body_protected: protected headers,
                    //     external_aad: empty bstr,
                    //     payload: payload
                    // ]
                    let sig_structure = Value::Array(vec![
                        Value::Text("Signature1".to_string()),
                        cose_array[0].clone(), // protected
                        Value::Bytes(vec![]),  // external_aad (empty)
                        cose_array[2].clone(), // payload
                    ]);

                    // 序列化 Sig_structure
                    let mut sig_structure_bytes = Vec::new();
                    ciborium::into_writer(&sig_structure, &mut sig_structure_bytes)?;

                    // 1. 使用 Signer 生成 DER 格式签名 (OpenSSL 默认行为)
                    let mut signer = Signer::new(MessageDigest::sha512(), signing_key)?;
                    signer.update(&sig_structure_bytes)?;
                    let der_signature = signer.sign_to_vec()?;

                    // 2. 解析 DER 格式为 ECDSA 对象 (r, s)
                    let ecdsa_sig = EcdsaSig::from_der(&der_signature)?;
                    let r = ecdsa_sig.r();
                    let s = ecdsa_sig.s();

                    // 3. 转换为固定长度的 Raw 格式 (P-521 需要 66 字节)
                    // ES512 (P-521) 的 Key Size 是 521 bits
                    // ceil(521 / 8) = 66 bytes
                    let mut r_bytes = r.to_vec_padded(66)?;
                    let mut s_bytes = s.to_vec_padded(66)?;

                    // 4. 拼接 r 和 s
                    let mut raw_signature = Vec::with_capacity(132);
                    raw_signature.append(&mut r_bytes);
                    raw_signature.append(&mut s_bytes);

                    // 更新签名字段为 Raw 格式
                    cose_array[3] = Value::Bytes(raw_signature);
                }

                // 重新序列化回 Value::Bytes
                let mut new_bytes = Vec::new();
                ciborium::into_writer(&cose_sign1, &mut new_bytes)?;
                *v = Value::Bytes(new_bytes);

                break;
            }
        }
        Ok(())
    }

    /// 辅助函数: 匹配 CBOR Integer label
    fn match_label(value: &Value, expected: i128) -> bool {
        if let Value::Integer(i) = value {
            let val: i128 = (*i).into();
            val == expected as i128
        } else {
            false
        }
    }

    /// 辅助函数: 从 Value 中提取 COSE_Sign1 数组
    /// 处理 Tag(18, Array) 或直接 Array
    fn extract_cose_array_from_value(
        value: &mut Value,
    ) -> Result<&mut Vec<Value>, Box<dyn std::error::Error>> {
        // 尝试提取 Tag(18, Array)
        if let Value::Tag(_tag, inner) = value {
            if let Value::Array(arr) = inner.as_mut() {
                return Ok(arr);
            }
        }
        Err("Expected COSE_Sign1 structure (Tag(18, Array) or Array)".into())
    }

    fn update_token_header_alg(
        &self,
        cose_array: &mut Vec<Value>,
        new_alg: i128,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // cose_array[0] 是 protected header (bytes)
        if let Value::Bytes(protected_bytes) = &cose_array[0] {
            // 1. 反序列化 Header Map
            let mut header_map: Value = ciborium::from_reader(&protected_bytes[..])?;

            if let Value::Map(map) = &mut header_map {
                let mut found = false;
                // 2. 查找并更新 alg 字段 (Key: 1)
                for (k, v) in map.iter_mut() {
                    if Self::match_label(k, COSE_HEADER_ALG) {
                        *v = Value::Integer(Integer::try_from(new_alg)?);
                        found = true;
                        break;
                    }
                }

                // 如果没找到 alg 字段（虽然模板通常都有），则插入
                if !found {
                    map.push((
                        Value::Integer(Integer::try_from(COSE_HEADER_ALG)?),
                        Value::Integer(Integer::try_from(new_alg)?),
                    ));
                }
            }

            // 3. 重新序列化 Header 并写回 cose_array[0]
            let mut new_header_bytes = Vec::new();
            ciborium::into_writer(&header_map, &mut new_header_bytes)?;
            cose_array[0] = Value::Bytes(new_header_bytes);
        }
        Ok(())
    }
}
