// src/token.rs

use crate::constants::*;
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::sign::Signer;
use openssl::hash::MessageDigest;
use openssl::bn::BigNumContext;
use sha2::{Sha512, Digest};
use ciborium::Value;
use coset::{AsCborValue, CoseSign};

pub struct TokenGenerator {
    platform_key: PKey<Private>,
}

impl TokenGenerator {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        // 加载平台私钥
        let platform_key = PKey::private_key_from_pem(PLATFORM_PRIV_KEY_PEM.as_bytes())?;
        Ok(Self { platform_key })
    }

    pub fn generate_token(&self, challenge: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        // 1. 解析模板 token
        let template_bytes = hex::decode(TEMPLATE_TOKEN_HEX.replace("\n", "").replace(" ", ""))?;
        let mut token: Value = ciborium::from_reader(&template_bytes[..])?;

        // 2. 生成临时 P-521 密钥对 (Realm Attestation Key)
        let group = EcGroup::from_curve_name(Nid::SECP521R1)?;
        let rak_ec_key = EcKey::generate(&group)?;
        let rak_pkey = PKey::from_ec_key(rak_ec_key.clone())?;

        // 3. 提取 RAK 公钥并转换为 x||y 格式 (各66字节)
        let mut bn_ctx = BigNumContext::new()?;

        let rak_pub_uncompressed = rak_ec_key.public_key().to_bytes(
            &group,
            openssl::ec::PointConversionForm::UNCOMPRESSED,
            &mut bn_ctx,
        )?;

        // P-521 未压缩格式: 0x04 || x (66 bytes) || y (66 bytes) = 133 bytes
        // 去掉第一个字节 0x04，提取 x 和 y
        let rak_pub_bytes = if rak_pub_uncompressed.len() == 133 && rak_pub_uncompressed[0] == 0x04 {
            rak_pub_uncompressed[1..].to_vec() // 66 bytes x || 66 bytes y = 132 bytes
        } else {
            return Err("Invalid P-521 public key format".into());
        };

        // 4. 计算 RAK 的 SHA-512 哈希 (使用 x||y 格式)
        let mut hasher = Sha512::new();
        hasher.update(&rak_pub_bytes);
        let rak_hash = hasher.finalize().to_vec();

        // 5. 修改 token 结构
        if let Value::Tag(399, inner) = &mut token {
            if let Value::Map(root_map) = inner.as_mut() {
                // 修改 Platform Token
                self.update_platform_token(root_map, &rak_hash)?;

                // 修改 Realm Token
                self.update_realm_token(root_map, challenge, &rak_pub_bytes)?;

                // 6. 对 Realm Token 进行签名
                self.sign_realm_token(root_map, &rak_pkey)?;

                // 7. 对 Platform Token 进行签名
                self.sign_platform_token(root_map)?;
            }
        }

        // 8. 序列化最终的 token
        let mut buffer = Vec::new();
        ciborium::into_writer(&token, &mut buffer)?;

        Ok(buffer)
    }

    fn update_platform_token(
        &self,
        root_map: &mut Vec<(Value, Value)>,
        rak_hash: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {


        // 遍历根 map，查找 PLATFORM_LABEL
        for (k, v) in root_map.iter_mut() {
            if let Value::Integer(i) = k {
                if i128::from(*i) == PLATFORM_LABEL {
                    // let cose_bytes = if let Value::Bytes(bytes) = v {
                    //     bytes
                    // } else {
                    //     continue;
                    // };

                    let mut pt = CoseSign::from_cbor_value(*v)?;
                    pt.signatures.

                    let mut cose_with_tag: Value = ciborium::from_reader(&cose_bytes[..])?;

                    // Platform Token 是 COSE_Sign1，可能是 Tag(18) 或直接是 Array
                    let mut cose_array = if let Value::Tag(_tag, mut inner) = cose_with_tag {
                        // 如果是 Tag，提取内部的 Array
                        if let Value::Array(arr) = inner.as_mut().clone() {
                            arr
                        } else {
                            continue;
                        }
                    } else {
                        continue;
                    };

                    // COSE_Sign1 结构: [protected, unprotected, payload, signature]
                    if cose_array.len() >= 3 {
                        if let Value::Bytes(payload_bytes) = &mut cose_array[2] {
                            // 解析 payload (Platform Claims)
                            let mut claims: Value = ciborium::from_reader(&payload_bytes[..])?;

                            // 更新 challenge 字段
                            if let Value::Map(claims_map) = &mut claims {
                                for (ck, cv) in claims_map.iter_mut() {
                                    if let Value::Integer(ci) = ck {
                                        if i128::from(*ci) == PLATFORM_CHALLENGE_LABEL {
                                            *cv = Value::Bytes(rak_hash.to_vec());
                                            break;
                                        }
                                    }
                                }
                            }

                            // 重新序列化 claims
                            let mut new_payload = Vec::new();
                            ciborium::into_writer(&claims, &mut new_payload)?;
                            *payload_bytes = new_payload;
                        }
                    }
                    break;
                }
            }
        }
        Ok(())
    }

    fn update_realm_token(
        &self,
        root_map: &mut Vec<(Value, Value)>,
        challenge: &[u8],
        rak_pub_bytes: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        // 遍历根 map，查找 REALM_LABEL
        for (k, v) in root_map.iter_mut() {
            if let Value::Integer(i) = k {
                if i128::from(*i) == REALM_LABEL {

                    let cose_bytes = if let Value::Bytes(bytes) = v {
                        bytes
                    } else {
                        continue;
                    };

                    let mut cose_with_tag: Value = ciborium::from_reader(&cose_bytes[..])?;

                    // Platform Token 是 COSE_Sign1，可能是 Tag(18) 或直接是 Array
                    let mut cose_array = if let Value::Tag(_tag, mut inner) = cose_with_tag {
                        // 如果是 Tag，提取内部的 Array
                        if let Value::Array(arr) = inner.as_mut().clone() {
                            arr
                        } else {
                            continue;
                        }
                    } else {
                        continue;
                    };

                    // COSE_Sign1 结构: [protected, unprotected, payload, signature]
                    if cose_array.len() >= 3 {
                        if let Value::Bytes(payload_bytes) = &mut cose_array[2] {
                            // 解析 payload (Realm Claims)
                            let mut claims: Value = ciborium::from_reader(&payload_bytes[..])?;

                            // 更新 challenge 和 RAK
                            if let Value::Map(claims_map) = &mut claims {
                                for (ck, cv) in claims_map.iter_mut() {
                                    if let Value::Integer(ci) = ck {
                                        let label = i128::from(*ci);
                                        if label == REALM_CHALLENGE_LABEL {
                                            *cv = Value::Bytes(challenge.to_vec());
                                        } else if label == REALM_RAK_LABEL {
                                            // RAK 字段: 66字节x + 66字节y
                                            *cv = Value::Bytes(rak_pub_bytes.to_vec());
                                        }
                                    }
                                }
                            }

                            // 重新序列化 claims
                            let mut new_payload = Vec::new();
                            ciborium::into_writer(&claims, &mut new_payload)?;
                            *payload_bytes = new_payload;
                        }
                    }
                    break;
                }
            }
        }
        Ok(())
    }

    fn sign_realm_token(
        &self,
        root_map: &mut Vec<(Value, Value)>,
        rak_key: &PKey<Private>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // 查找 Realm Token 并签名
        for (k, v) in root_map.iter_mut() {
            if let Value::Integer(i) = k {
                if i128::from(*i) == REALM_LABEL {
                    let cose_array = if let Value::Tag(_tag, inner) = v {
                        if let Value::Array(arr) = inner.as_mut() {
                            arr
                        } else {
                            continue;
                        }
                    } else if let Value::Array(arr) = v {
                        arr
                    } else {
                        continue;
                    };

                    if cose_array.len() >= 4 {
                        // 构造 Sig_structure for COSE_Sign1
                        // Sig_structure = [
                        //     context = "Signature1",
                        //     body_protected,
                        //     external_aad = b"",
                        //     payload
                        // ]
                        let protected = &cose_array[0];
                        let payload = &cose_array[2];

                        let sig_structure_array = Value::Array(vec![
                            Value::Text("Signature1".to_string()),
                            protected.clone(),
                            Value::Bytes(vec![]),
                            payload.clone(),
                        ]);

                        let mut sig_structure_bytes = Vec::new();
                        ciborium::into_writer(&sig_structure_array, &mut sig_structure_bytes)?;

                        // 使用 RAK 私钥签名
                        let mut signer = Signer::new(MessageDigest::sha512(), rak_key)?;
                        signer.update(&sig_structure_bytes)?;
                        let signature = signer.sign_to_vec()?;

                        // 更新签名
                        cose_array[3] = Value::Bytes(signature);
                    }
                    break;
                }
            }
        }
        Ok(())
    }

    fn sign_platform_token(
        &self,
        root_map: &mut Vec<(Value, Value)>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // 查找 Platform Token 并使用平台私钥重新签名
        for (k, v) in root_map.iter_mut() {
            if let Value::Integer(i) = k {
                if i128::from(*i) == PLATFORM_LABEL {
                    let cose_array = if let Value::Tag(_tag, inner) = v {
                        if let Value::Array(arr) = inner.as_mut() {
                            arr
                        } else {
                            continue;
                        }
                    } else if let Value::Array(arr) = v {
                        arr
                    } else {
                        continue;
                    };

                    if cose_array.len() >= 4 {
                        // 构造 Sig_structure for COSE_Sign1
                        let protected = &cose_array[0];
                        let payload = &cose_array[2];

                        let sig_structure_array = Value::Array(vec![
                            Value::Text("Signature1".to_string()),
                            protected.clone(),
                            Value::Bytes(vec![]),
                            payload.clone(),
                        ]);

                        let mut sig_structure_bytes = Vec::new();
                        ciborium::into_writer(&sig_structure_array, &mut sig_structure_bytes)?;

                        // 使用平台私钥签名
                        let mut signer = Signer::new(MessageDigest::sha512(), &self.platform_key)?;
                        signer.update(&sig_structure_bytes)?;
                        let signature = signer.sign_to_vec()?;

                        // 更新签名
                        cose_array[3] = Value::Bytes(signature);
                    }
                    break;
                }
            }
        }
        Ok(())
    }
}