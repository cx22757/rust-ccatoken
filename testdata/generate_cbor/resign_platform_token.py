import sys
import cbor2
import base64
from cbor2 import CBORTag
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils  # 新增导入 utils

# === 配置参数 ===
TAG_CCA_TOKEN = 399
KEY_PLATFORM_TOKEN = 44234
ALG_ES512 = -36
HEADER_ALG = 1

# === 文件路径 ===
INPUT_FILE = "../cca-token-01.cbor"
PRIVATE_KEY_PATH = "./mock_keys_p521/platform.key"
OUTPUT_BIN_FILE = "cca_token_mock_p521.cbor"

def resign_and_encode():
    # 1. 加载私钥
    print(f"[*] 加载 P-521 私钥: {PRIVATE_KEY_PATH}")
    try:
        with open(PRIVATE_KEY_PATH, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
    except FileNotFoundError:
        print(f"[X] 错误: 找不到私钥文件 {PRIVATE_KEY_PATH}")
        return

    # 2. 读取原始 Token
    print(f"[*] 解析输入文件: {INPUT_FILE}")
    try:
        with open(INPUT_FILE, "rb") as f:
            cca_obj = cbor2.load(f)
    except FileNotFoundError:
        print(f"[X] 错误: 找不到输入文件 {INPUT_FILE}")
        return

    # --- 结构解析 ---
    if isinstance(cca_obj, CBORTag):
        token_map = cca_obj.value
        outer_tag = cca_obj.tag
    else:
        token_map = cca_obj
        outer_tag = TAG_CCA_TOKEN

    if KEY_PLATFORM_TOKEN not in token_map:
        raise ValueError(f"错误: 未找到 Platform Token (Key {KEY_PLATFORM_TOKEN})")

    raw_cose_bytes = token_map[KEY_PLATFORM_TOKEN]
    cose_obj = cbor2.loads(raw_cose_bytes)

    original_tag_value = 18
    if isinstance(cose_obj, CBORTag):
        original_tag_value = cose_obj.tag
        cose_arr = cose_obj.value
    else:
        cose_arr = cose_obj

    prot_header_bytes = cose_arr[0]
    unprot_header_map = cose_arr[1]
    payload_bytes = cose_arr[2]

    # --- 重签逻辑 ---
    print("[*] 正在使用 P-521 私钥重新签名并转换为 Raw 格式...")
    
    # 修改算法头为 ES512
    prot_map = cbor2.loads(prot_header_bytes) if prot_header_bytes else {}
    prot_map[HEADER_ALG] = ALG_ES512
    new_prot_header_bytes = cbor2.dumps(prot_map)

    # 构造 Sig_Structure
    sig_structure = [
        "Signature1",
        new_prot_header_bytes,
        b"",
        payload_bytes
    ]
    tbs_bytes = cbor2.dumps(sig_structure)

    # --- 核心修复点：DER 转 Raw (r || s) ---
    # 1. 执行签名得到 DER 格式
    der_signature = private_key.sign(tbs_bytes, ec.ECDSA(hashes.SHA512()))
    
    # 2. 从 DER 中提取 r 和 s 整数
    r, s = utils.decode_dss_signature(der_signature)
    
    # 3. 转换为大端字节序并拼接。P-521 对应的长度是 66 字节
    # new_signature 长度应严格为 132 字节
    new_signature = r.to_bytes(66, 'big') + s.to_bytes(66, 'big')
    
    print(f"[*] 签名转换成功: DER({len(der_signature)} bytes) -> Raw({len(new_signature)} bytes)")

    # 重组 COSE
    new_cose_arr = [
        new_prot_header_bytes,
        unprot_header_map,
        payload_bytes,
        new_signature
    ]
    new_cose_obj = CBORTag(original_tag_value, new_cose_arr)
    new_cose_bytes = cbor2.dumps(new_cose_obj)

    # 更新 Map
    token_map[KEY_PLATFORM_TOKEN] = new_cose_bytes

    # --- 最终序列化 ---
    final_cbor_obj = CBORTag(outer_tag, token_map)
    final_cbor_bytes = cbor2.dumps(final_cbor_obj)

    # 1. 保存原始二进制文件
    with open(OUTPUT_BIN_FILE, "wb") as f:
        f.write(final_cbor_bytes)
    print(f"[*] 原始二进制文件已保存: {OUTPUT_BIN_FILE}")

    # 2. 生成 C 语言 Byte Array
    hex_list = [f"0x{b:02X}" for b in final_cbor_bytes]
    token_len = len(hex_list)
    write_common_h(hex_list, token_len)

def write_common_h(hex_list, token_len):
    with open("common.h", "w") as f:
        f.write("#ifndef COMMON_H\n#define COMMON_H\n\n")
        f.write("#include <stddef.h>\n\n")
        f.write(f"// Generated from {OUTPUT_BIN_FILE}\n")
        f.write(f"static const size_t MOCK_TOKEN_LEN = {token_len};\n")
        f.write("static const unsigned char MOCK_TOKEN_DATA[] = {\n")
        # 为了美观，每行写 16 个字节
        for i in range(0, len(hex_list), 16):
            chunk = hex_list[i:i+16]
            f.write("    " + ", ".join(chunk) + ",\n")
        f.write("};\n\n")
        
        # 同时把证书也写进去 (假设证书在固定位置)
        cert_path = "./mock_keys_p521/platform.crt"
        try:
            with open(cert_path, "r") as cf:
                cert_lines = cf.read().splitlines()
            f.write("// Platform Certificate\n")
            f.write("#define MOCK_CERT_PEM \\\n")
            for line in cert_lines:
                f.write(f'"{line}\\n" \\\n')
            f.write('""\n') # 结束空字符串防止末尾反斜杠问题
        except:
            f.write("// Warning: Certificate file not found during generation\n")
            f.write('#define MOCK_CERT_PEM ""\n')

        f.write("\n#endif // COMMON_H\n")
    
    print(f"[*] 已自动生成头文件: common.h (包含 Token 数组和证书宏)")

if __name__ == "__main__":
    try:
        resign_and_encode()
    except Exception as e:
        print(f"[X] 发生异常: {e}")