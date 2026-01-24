#!/bin/bash

# 设置输出目录
OUT_DIR="./mock_keys_p521"
mkdir -p $OUT_DIR

# === 配置参数 ===
# [修改点] 使用 NIST P-521 曲线
# 在 OpenSSL 中，NIST P-521 对应的名称通常是 secp521r1
ECC_CURVE="secp521r1"

# 证书有效期 (天)
DAYS=3650

echo "=== 开始生成 Mock CCA 密钥与证书 (Curve: $ECC_CURVE) ==="
echo "输出目录: $OUT_DIR"

# ---------------------------------------------------------
# 1. 生成 CA (Certificate Authority)
# ---------------------------------------------------------
echo -e "\n[1] 生成 CA 私钥和自签名证书..."

# 生成 CA 私钥
openssl ecparam -name $ECC_CURVE -genkey -noout -out $OUT_DIR/ec_ca.key

# 生成 CA 自签名证书
openssl req -new -x509 -key $OUT_DIR/ec_ca.key -out $OUT_DIR/ec_ca.crt -days $DAYS \
    -subj "/C=CN/O=MockOrg/CN=Mock_CCA_Root_CA_P521"

echo " -> CA 私钥: $OUT_DIR/ec_ca.key"
echo " -> CA 证书: $OUT_DIR/ec_ca.crt"

# ---------------------------------------------------------
# 2. 生成 Platform Key (用于 Token 签名)
# ---------------------------------------------------------
echo -e "\n[2] 生成 Platform 私钥..."

# 生成 Platform 私钥
openssl ecparam -name $ECC_CURVE -genkey -noout -out $OUT_DIR/platform.key

echo " -> Platform 私钥: $OUT_DIR/platform.key"

# ---------------------------------------------------------
# 3. 使用 CA 签发 Platform 证书
# ---------------------------------------------------------
echo -e "\n[3] 生成 CSR 并使用 CA 签发 Platform 证书..."

# 生成证书签名请求 (CSR)
openssl req -new -key $OUT_DIR/platform.key -out $OUT_DIR/platform.csr \
    -subj "/C=CN/O=MockOrg/CN=Mock_CCA_Platform_P521"

# 准备扩展配置文件
cat > $OUT_DIR/extfile.cnf << EOF
basicConstraints = CA:FALSE
keyUsage = digitalSignature, nonRepudiation
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EOF

# 使用 CA 签署 CSR
# 注意：这里使用 sha512 进行摘要签名，以匹配 P-521 的强度
openssl x509 -req -in $OUT_DIR/platform.csr \
    -CA $OUT_DIR/ec_ca.crt -CAkey $OUT_DIR/ec_ca.key -CAcreateserial \
    -out $OUT_DIR/platform.crt -days $DAYS \
    -sha512 \
    -extfile $OUT_DIR/extfile.cnf

echo " -> Platform 证书: $OUT_DIR/platform.crt"

# ---------------------------------------------------------
# 4. 验证与清理
# ---------------------------------------------------------
echo -e "\n[4] 验证证书链..."
openssl verify -CAfile $OUT_DIR/ec_ca.crt $OUT_DIR/platform.crt

# 清理中间文件
rm $OUT_DIR/platform.csr $OUT_DIR/extfile.cnf $OUT_DIR/ec_ca.srl 2>/dev/null

echo -e "\n=== 完成！ ==="
echo "注意：在您的 Mock SDK 代码中，COSE 算法 ID 需要设置为 ES512 (Alg ID: -36)"