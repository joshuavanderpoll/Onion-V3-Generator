import base64
import hashlib
import os
import threading
import time
import sys
import select
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, PublicFormat
import argparse
class OnionGenerator:
    generated_count = 0
    found_count = 0
    @staticmethod
    def generate_address():
        # Generate key pair
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        # Serialize keys
        private_bytes = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        public_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

        # Expand secret key
        expanded_secret_key = OnionGenerator.expand_secret_key(private_bytes)

        # Generate onion address
        onion_address = OnionGenerator.encode_public_key(public_bytes)

        public = b"== ed25519v1-public: type0 ==\x00\x00\x00" + public_bytes
        secret = b"== ed25519v1-secret: type0 ==\x00\x00\x00" + expanded_secret_key

        OnionGenerator.generated_count += 1

        return {
            "hostname": onion_address,
            "public": base64.b64encode(public).decode(),
            "private": base64.b64encode(secret).decode()
        }
    @staticmethod
    def generate_with_prefix(prefixes):
        while True:
            generated = OnionGenerator.generate_address()
            for prefix in prefixes:
                if generated["hostname"].startswith(prefix):
                    OnionGenerator.found_count += 1
                    return generated
    @staticmethod
    def encode_public_key(public_key):
        checksum = hashlib.sha3_256(b".onion checksum" + public_key + b"\x03").digest()[:2]
        onion_address = public_key + checksum + b"\x03"
        return OnionGenerator.base32_encode(onion_address).lower() + ".onion"
    @staticmethod
    def expand_secret_key(secret_key):
        # Expand the secret key to meet the required format
        hash_bytes = hashlib.sha512(secret_key).digest()
        hash_list = list(hash_bytes)
        hash_list[0] &= 248
        hash_list[31] &= 127
        hash_list[31] |= 64

        return bytes(hash_list)
    @staticmethod
    def base32_encode(data):
        # Base32 encode the data
        return base64.b32encode(data).decode('utf-8').strip("=")
def save_result(result, output_dir):
    address_dir = os.path.join(output_dir, result["hostname"].removesuffix(".onion"))
    os.makedirs(address_dir, exist_ok=True)

    with open(os.path.join(address_dir, "hostname"), "w") as f:
        f.write(result["hostname"] + "\n")

    with open(os.path.join(address_dir, "hs_ed25519_public_key.b64"), "w") as f:
        f.write(result["public"] + "\n")

    with open(os.path.join(address_dir, "hs_ed25519_secret_key.b64"), "w") as f:
        f.write(result["private"] + "\n")

    return address_dir
def periodic_update(interval):
    while True:
        time.sleep(interval)
        print(f"[@] {time.strftime('%H:%M:%S')}: Generated {OnionGenerator.generated_count} addresses, Found {OnionGenerator.found_count} addresses")
def keypress_update():
    if not sys.stdin.isatty():
        print("[!] Non-TTY environment detected. Keypress updates are disabled.\n")
        return
    print("[i] Press Enter to see the current status:\n")
    while True:
        if select.select([sys.stdin], [], [], 0.1)[0]:
            sys.stdin.read(1)
            print(f"[@] {time.strftime('%H:%M:%S')}: Generated {OnionGenerator.generated_count} addresses, Found {OnionGenerator.found_count} addresses")
def main():
    parser = argparse.ArgumentParser(description="Generate Tor .onion addresses.")
    parser.add_argument("prefixes", nargs="+", help="List of prefixes for the hostname")
    parser.add_argument("-o", "--output-dir", default="onion_keys",
                         help="Directory to save found keys into (default: onion_keys)")
    args = parser.parse_args()
    # Ensure at least one prefix is provided
    if not args.prefixes:
        print("[!] Error: At least one prefix must be provided.")
        sys.exit(1)
    prefixes = [prefix.strip().lower() for prefix in args.prefixes]
    os.makedirs(args.output_dir, exist_ok=True)
    # Start threads
    threading.Thread(target=periodic_update, args=(30,), daemon=True).start()
    threading.Thread(target=keypress_update, daemon=True).start()
    try:
        print("[@] Generating addresses...")
        while True:
            result = OnionGenerator.generate_with_prefix(prefixes)
            saved_path = save_result(result, args.output_dir)
            print('[√] Address generated successfully!')
            print(f"Hostname:                      {result['hostname']}")
            print(f"Public Key (Base64 encoded):   {result['public']}")
            print(f"Private Key (Base64 encoded):  {result['private']}")
            print(f"Saved to:                      {saved_path}\n")
    except KeyboardInterrupt:
        print("[!] Stopping generation...")
if __name__ == "__main__":
    main()
