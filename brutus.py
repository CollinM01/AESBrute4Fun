import base64
import itertools
import multiprocessing as mp
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad

# REQUIRED for Python 3.12 multiprocessing to work with pycryptodome
mp.set_start_method("forkserver", force=True)

# Encrypted samples (Base64) and known plaintexts
samples = [
    ("VFVSUmVrMVVWWGhQVkUwOQ==", 2728513142),
    ("VG1wQmVFMVVWWGhQVkUwOQ==", 2630253647),
    ("VDFSak1VNXFhM2hQVkUwOQ==", 2171951344),
]

# Decode Base64 into binary ciphertexts
decoded_samples = [(base64.b64decode(b64), expected) for b64, expected in samples]

# Check if decrypted output is a numeric string
def is_numeric_bytes(data):
    try:
        return data.decode().strip().isdigit()
    except:
        return False

# Worker function for each AES key
def test_key(key_tuple):
    key = bytes(key_tuple).ljust(16, b'\0')
    cipher = AES.new(key, AES.MODE_ECB)
    try:
        for ct, _ in decoded_samples:
            pt = unpad(cipher.decrypt(ct), 16)
            if not is_numeric_bytes(pt):
                return None
        return key
    except Exception:
        return None

# Key generator (streaming)
def generate_keys(length):
    return itertools.product(range(256), repeat=length)

# Main brute-force function
def brute_force(max_key_len=4):
    for key_len in range(1, max_key_len + 1):
        print(f"\n🔍 Brute-forcing AES keys of length {key_len}...")
        key_generator = generate_keys(key_len)

        with mp.Pool(mp.cpu_count()) as pool:
            for i, result in enumerate(pool.imap_unordered(test_key, key_generator, chunksize=1000)):
                if i % 10000 == 0 and i > 0:
                    print(f"🔄 Tested {i:,} keys at length {key_len}...")

                if result:
                    print(f"\n✅ Key found: {result.hex()}")
                    cipher = AES.new(result, AES.MODE_ECB)
                    for b64, _ in samples:
                        ct = base64.b64decode(b64)
                        pt = unpad(cipher.decrypt(ct), 16)
                        print(f"{b64} → {pt.decode().strip()}")
                    pool.terminate()
                    return
        print(f"❌ No valid key found at length {key_len}")
    print("❌ Exhausted all key lengths.")

if __name__ == "__main__":
    brute_force(max_key_len=16)