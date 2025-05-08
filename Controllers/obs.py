import os
import json
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

KEY_FILE = 'secret.key'


def load_or_create_key(key_file: str) -> bytes:
    if os.path.exists(key_file):
        with open(key_file, 'rb') as f:
            key = f.read()
            if len(key) != 32:
                raise ValueError(f"Invalid key length: {len(key)} bytes; expected 32 bytes.")
            return key

    key = get_random_bytes(32)
    with open(key_file, 'wb') as f:
        f.write(key)
    return key


def encrypt_two_base64(s1: str, s2: str, key: bytes) -> str:
    payload = json.dumps({'a': s1, 'b': s2}).encode('utf-8')
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(payload, AES.block_size))
    return base64.b64encode(iv + ciphertext).decode('ascii')


def decrypt_two_base64(token_b64: str, key: bytes) -> (str, str):
    data = base64.b64decode(token_b64)
    iv, ct = data[:AES.block_size], data[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    payload = unpad(cipher.decrypt(ct), AES.block_size)
    obj = json.loads(payload.decode('utf-8'))
    return obj['a'], obj['b']


if __name__ == "__main__":
    secret_key = load_or_create_key(KEY_FILE)
    print("[INFO] AES-256 key loaded/generated, length:", len(secret_key), "bytes")

    s1 = "s5JPnzxMKIDANAa3YgZjVg=="
    s2 = "3vkTvTDC6VajB7GQTbGF1A=="

    token = encrypt_two_base64(s1, s2, secret_key)
    print("\nEncrypted token:\n", token)

    a, b = decrypt_two_base64(token, secret_key)
    print("\nDecrypted values:\n", a, b)

    b64_key = base64.b64encode(secret_key).decode('ascii')
    print("\nBase64-encoded key for transport:\n", b64_key)

    client_key = base64.b64decode(b64_key)
    assert client_key == secret_key, "Decoded key does not match original"
    print("\nClient key decoded successfully, matches the server key.")
