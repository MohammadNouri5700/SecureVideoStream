import os
import json
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import secrets
import ffmpeg


KEY_FILE = 'output/secret.key'
SPLIT_POS = 44  # Position to insert Base64 key into token
KEY_B64_LENGTH = 44  # Base64 length of a 32-byte key
key_data = secrets.token_bytes(16)
iv_data  = secrets.token_bytes(16)

def create_key_info_file(output_dir, key, iv):
    key_file = os.path.join(output_dir, "key.key")
    with open(key_file, "wb") as f:
        f.write(key)

    key_info_path = os.path.join(output_dir, "key_info")
    with open(key_info_path, "w") as f:
        f.write(f"{key_file}\n")
        f.write(f"{key_file}\n")
        f.write(iv.hex() + "\n")

    return key_info_path

def encrypt_hls(input_file, output_dir, segment_duration=30, base="http://192.168.122.1:50051/segment/Videos/asli/"):
    if not os.path.isfile(input_file):
        raise FileNotFoundError(f"File '{input_file}' not found")

    os.makedirs(output_dir, exist_ok=True)
    key_info = create_key_info_file(output_dir, key_data, iv_data)
    playlist = os.path.join(output_dir, "output.m3u8")

    (
        ffmpeg
        .input(input_file)
        .output(
            playlist,
            format='hls',
            hls_time=segment_duration,
            hls_key_info_file=key_info,
            hls_segment_filename=os.path.join(output_dir, 'segment_%03d.ts'),
            hls_base_url=base,
            vcodec="copy",
            acodec="aac"
        )
        .run(quiet=False)
    )
    
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


def merge_token_and_key(token: str, b64_key: str) -> str:
    if len(b64_key) != KEY_B64_LENGTH:
        raise ValueError(f"Base64 key length must be {KEY_B64_LENGTH}, got {len(b64_key)}")
    if len(token) < SPLIT_POS:
        raise ValueError(f"Token length must be >= {SPLIT_POS}")
    return token[:SPLIT_POS] + b64_key + token[SPLIT_POS:]


def split_token_and_key(merged: str) -> (str, str):
    if len(merged) < SPLIT_POS + KEY_B64_LENGTH:
        raise ValueError("Merged string is too short")
    b64_key = merged[SPLIT_POS:SPLIT_POS+KEY_B64_LENGTH]
    token = merged[:SPLIT_POS] + merged[SPLIT_POS+KEY_B64_LENGTH:]
    return token, b64_key


if __name__ == "__main__":

    # print("Base64-encoded AES-128 Key:", base64.b64encode(key_data).decode())
    # print("Base64-encoded AES IV:   ", base64.b64encode(iv_data).decode())
    encrypt_hls("your_video.mp4", "output")

    playlist_path = "output/output.m3u8"
    with open(playlist_path, "r", encoding="utf-8") as f:
        lines = [l for l in f if not l.startswith("#EXT-X-KEY:")]
    with open(playlist_path, "w", encoding="utf-8") as f:
        f.writelines(lines)


    # Load or generate AES-256 key
    secret_key = load_or_create_key(KEY_FILE)
    # print(f"[INFO] AES-256 key loaded/generated, length: {len(secret_key)} bytes")

    # Encrypt
    token = encrypt_two_base64(base64.b64encode(key_data).decode(), base64.b64encode(iv_data).decode(), secret_key)
    # print(f"\nEncrypted token:\n{token}")

    # Base64-encode key
    b64_key = base64.b64encode(secret_key).decode('ascii')
  

    # Merge token and key
    merged = merge_token_and_key(token, b64_key)
    print(f"\ntransport:\n{merged}")

    # Split merged
    recovered_token, recovered_b64_key = split_token_and_key(merged)
    assert recovered_token == token
    assert recovered_b64_key == b64_key
    print("\nRecovered token and key match originals.")

    os.remove("output/key.key")
    os.remove("output/key_info")
    os.remove("output/secret.key")
    # # Simulate client decrypt
    # client_key = base64.b64decode(recovered_b64_key)
    # a, b = decrypt_two_base64(recovered_token, client_key)
    # print(f"\nDecrypted values on client:\n a={a}\n b={b}")
