// src/token.rs

use crate::constants::*;
use ciborium::Value;
use coset::{
    iana, Algorithm, CborSerializable, CoseKey, CoseSign1, KeyOperation,
    KeyType, Label, TaggedCborSerializable,
};
use openssl::bn::BigNumContext;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::{hash, MessageDigest};
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::sign::Signer;

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
        // 1. 解析模板 token (CBOR Map)
        // 注意：模板可能包含空格或换行，先清理
        let template_bytes = hex::decode(TEMPLATE_TOKEN_HEX.replace(['\n', ' '], ""))?;
        let mut token: Value = ciborium::from_reader(&template_bytes[..])?;

        // 2. 生成临时 P-521 密钥对 (Realm Attestation Key - RAK)
        let group = EcGroup::from_curve_name(Nid::SECP521R1)?;
        let rak_ec_key = EcKey::generate(&group)?;
        let rak_pkey = PKey::from_ec_key(rak_ec_key.clone())?;

        // 3. 提取 RAK 公钥
        let mut bn_ctx = BigNumContext::new()?;
        let rak_pub_uncompressed = rak_ec_key.public_key().to_bytes(
            &group,
            openssl::ec::PointConversionForm::UNCOMPRESSED,
            &mut bn_ctx,
        )?;

        // P-521 未压缩格式: 0x04 || x (66 bytes) || y (66 bytes) = 133 bytes
        // 去掉第一个字节 0x04，提取 x 和 y
        let rak_pub_bytes = if rak_pub_uncompressed.len() == 133 && rak_pub_uncompressed[0] == 0x04 {
            rak_pub_uncompressed.to_vec()
        } else {
            return Err("Invalid P-521 public key format".into());
        };

        // 4. 计算 RAK 的 SHA-256 哈希 (用于绑定到 Platform Token)
        let rak_hash = hash(MessageDigest::sha256(), &rak_pub_bytes)?;

        // 5. 修改 token 结构
        // 这一步假设根是一个 Tag 399 包裹的 Map
        if let Value::Tag(399, inner) = &mut token {
            if let Value::Map(root_map) = inner.as_mut() {

                // --- 修改 Platform Token (注入 RAK Hash) ---
                self.update_platform_token(root_map, &rak_hash)?;

                // --- 修改 Realm Token (注入 Challenge 和 RAK Key) ---
                // 这里我们传入 Ciborium Value 格式的 RAK Map，以便插入 Payload
                self.update_realm_token(root_map, challenge, rak_pub_bytes.as_slice())?;

                // --- 对 Realm Token 进行签名 (使用 RAK 私钥) ---
                self.sign_token(root_map, REALM_LABEL, &rak_pkey)?;

                // --- 对 Platform Token 进行签名 (使用 Platform 私钥) ---
                self.sign_token(root_map, PLATFORM_LABEL, &self.platform_key)?;
            }
        }

        // 8. 序列化最终的 token
        let mut buffer = Vec::new();
        ciborium::into_writer(&token, &mut buffer)?;

        Ok(buffer)
    }

    /// 辅助函数：将 OpenSSL ECKey 转换为 coset::CoseKey
    fn create_cose_key(&self, ec_key: &EcKey<Private>) -> Result<CoseKey, Box<dyn std::error::Error>> {
        let group = ec_key.group();
        let pub_key = ec_key.public_key();
        let mut ctx = BigNumContext::new()?;

        let mut x = openssl::bn::BigNum::new()?;
        let mut y = openssl::bn::BigNum::new()?;
        pub_key.affine_coordinates_gfp(group, &mut x, &mut y, &mut ctx)?;

        Ok(CoseKey {
            kty: KeyType::Assigned(iana::KeyType::EC2),
            key_ops: vec![KeyOperation::Assigned(iana::KeyOperation::Verify)].into_iter().collect(),
            alg: Some(Algorithm::Assigned(iana::Algorithm::ES512)), // ECDSA 512
            params: vec![
                (Label::Int(iana::Ec2KeyParameter::Crv as i64),  i128::into(iana::EllipticCurve::P_521 as i128)),
                (Label::Int(iana::Ec2KeyParameter::X as i64), Value::Bytes(x.to_vec())),
                (Label::Int(iana::Ec2KeyParameter::Y as i64), Value::Bytes(y.to_vec())),
            ],
            ..Default::default()
        })
    }

    /// 更新 Platform Token 的 Claims
    fn update_platform_token(
        &self,
        root_map: &mut Vec<(Value, Value)>,
        rak_hash: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let label_val = i128::into(PLATFORM_LABEL);

        // 查找对应的 Token (Value::Bytes)
        if let Some((_, v)) = root_map.iter_mut().find(|(k, _)| k == &label_val) {
            if let Value::Bytes(bytes) = v {
                // 1. 解析: Bytes -> CoseSign1 (支持 Tagged)
                let mut sign1 = CoseSign1::from_tagged_slice(bytes)
                    .map_err(|e| format!("Failed to parse Platform CoseSign1: {}", e))?;

                // 2. 提取 Payload 并反序列化为 Map
                // sign1.payload 是 Option<Vec<u8>>
                if let Some(payload_bytes) = &sign1.payload {
                    let mut claims: Value = ciborium::from_reader(payload_bytes.as_slice())?;

                    if let Value::Map(claims_map) = &mut claims {
                        // 3. 更新 Challenge
                        for (ck, cv) in claims_map.iter_mut() {
                            if *ck == i128::into(PLATFORM_CHALLENGE_LABEL) {
                                *cv = Value::Bytes(rak_hash.to_vec());
                                break;
                            }
                        }
                    }

                    // 4. 重新序列化 Claims 并存回 Payload
                    let mut new_payload = Vec::new();
                    ciborium::into_writer(&claims, &mut new_payload)?;
                    sign1.payload = Some(new_payload);
                }

                // 5. 序列化回 Bytes 更新 root_map
                *bytes = sign1.to_tagged_vec()
                    .map_err(|e| format!("Failed to serialize Platform CoseSign1: {}", e))?;
            }
        }
        Ok(())
    }

    /// 更新 Realm Token 的 Claims
    fn update_realm_token(
        &self,
        root_map: &mut Vec<(Value, Value)>,
        challenge: &[u8],
        rak: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let label_val = i128::into(REALM_LABEL);

        if let Some((_, v)) = root_map.iter_mut().find(|(k, _)| k == &label_val) {
            if let Value::Bytes(bytes) = v {
                // 1. 解析
                let mut sign1 = CoseSign1::from_tagged_slice(bytes)
                    .map_err(|e| format!("Failed to parse Realm CoseSign1: {}", e))?;

                // 2. 修改 Payload
                if let Some(payload_bytes) = &sign1.payload {
                    let mut claims: Value = ciborium::from_reader(payload_bytes.as_slice())?;

                    if let Value::Map(claims_map) = &mut claims {
                        for (ck, cv) in claims_map.iter_mut() {
                            if *ck == i128::into(REALM_CHALLENGE_LABEL) {
                                // 替换challenge
                                *cv = Value::Bytes(challenge.to_vec());
                            } else if *ck == i128::into(REALM_RAK_LABEL) {
                                // 替换rak
                                *cv = Value::Bytes(rak.to_vec());
                            }
                        }
                    }

                    // 3. 存回 Payload
                    let mut new_payload = Vec::new();
                    ciborium::into_writer(&claims, &mut new_payload)?;
                    sign1.payload = Some(new_payload);
                }

                // 4. 保存
                *bytes = sign1.to_tagged_vec()
                    .map_err(|e| format!("Failed to serialize Realm CoseSign1: {}", e))?;
                *v = Value::Bytes(bytes.to_vec());
            }
        }
        Ok(())
    }

    /// 通用的签名函数 (合并了原来的 sign_realm 和 sign_platform)
    fn sign_token(
        &self,
        root_map: &mut Vec<(Value, Value)>,
        token_label: i128,
        signing_key: &PKey<Private>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let label_val = i128::into(token_label);

        if let Some((_, v)) = root_map.iter_mut().find(|(k, _)| k == &label_val) {
            if let Value::Bytes(bytes) = v {
                // 1. 解析
                let mut sign1 = CoseSign1::from_tagged_slice(bytes)
                    .map_err(|e| format!("Failed to parse CoseSign1 for signing: {}", e))?;

                // 2. 清除旧签名 (可选，但在重签时是好习惯)
                sign1.signature = vec![];

                // 3. 生成待签名数据 (TBS)
                // external_aad 为空，符合 CCA 规范
                let tbs_data = sign1.tbs_data(&[]);
                let tbs_bytes = tbs_data.to_vec();

                // 4. 执行签名 (SHA-512)
                let mut signer = Signer::new(MessageDigest::sha512(), signing_key)?;
                signer.update(&tbs_bytes)?;
                let signature = signer.sign_to_vec()?;

                // 5. 填回签名
                sign1.signature = signature;

                // 6. 保存回 root_map
                *bytes = sign1.to_tagged_vec()
                    .map_err(|e| format!("Failed to serialize signed CoseSign1: {}", e))?;
            }
        }
        Ok(())
    }
}