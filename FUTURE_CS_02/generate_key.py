from base64 import b64encode
from Crypto.Random import get_random_bytes

key = get_random_bytes(32)
encoded_key = b64encode(key).decode('utf-8')

with open(".env", "w") as f:
    f.write(f"AES_KEY={encoded_key}")

    print("AES key generated and saved to .env")

