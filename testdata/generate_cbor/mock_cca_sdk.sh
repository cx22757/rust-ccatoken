#! /bin/bash

python3 resign_platform_token.py

gcc -shared -fPIC -o libmock_cca_sdk.so mock_cca_sdk.c
echo "[*] 已编译libmock_cca_sdk.so"