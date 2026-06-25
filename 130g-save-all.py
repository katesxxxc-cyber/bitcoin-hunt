import random
import binascii
from ecdsa import SigningKey, VerifyingKey, SECP256k1
import os
import atexit
import time

USED_KEYS_FILE = "used_keys.txt"
used_private_keys = set()

def generate_private_key_in_range(start_range, end_range):
    """Generates a private key within a specified range.

    Args:
        start_range (int): The lower bound of the range for private key generation.
        end_range (int): The upper bound of the range for private key generation.

    Returns:
        str: The generated private key in hexadecimal format.
    """
    # Generate a random integer in the specified range [start_range, end_range]
    private_key_int = random.randint(start_range, end_range)

    # Convert the integer to hexadecimal format
    private_key_hex = hex(private_key_int)[2:].zfill(64)  # 64 characters (32 bytes)

    return private_key_hex

def compute_public_key(private_key_hex, compressed=True):
    """Computes the public key from a given private key.

    Args:
        private_key_hex (str): The private key in hexadecimal format.
        compressed (bool): Whether to compute the public key in compressed format.

    Returns:
        str: The computed public key in hexadecimal format.
    """
    # Convert the private key from hexadecimal to bytes
    private_key_bytes = binascii.unhexlify(private_key_hex)

    # Generate the signing key from the private key bytes
    sk = SigningKey.from_string(private_key_bytes, curve=SECP256k1)

    # Get the verifying key
    vk = sk.verifying_key

    # Compute the public key in compressed or uncompressed format
    if compressed:
        public_key = vk.to_string("compressed")
    else:
        public_key = vk.to_string("uncompressed")

    # Convert the public key bytes to hexadecimal format
    public_key_hex = binascii.hexlify(public_key).decode('utf-8')

    return public_key_hex

def find_private_key(public_key_hex, start_range, end_range):
    """Attempts to find the private key corresponding to a given public key within a specified range.

    Args:
        public_key_hex (str): The public key in hexadecimal format (compressed).
        start_range (int): The lower bound of the range for private key generation.
        end_range (int): The upper bound of the range for private key generation.

    Returns:
        str: The computed private key if found, or None if not found.
    """
    global used_private_keys
    # Convert the public key from hexadecimal to bytes
    public_key_bytes = binascii.unhexlify(public_key_hex)

    # Create a verifying key object
    vk = VerifyingKey.from_string(public_key_bytes, curve=SECP256k1)

    # Attempt to find the private key within the specified range
    while True:
        private_key_hex = generate_private_key_in_range(start_range + random.randint(1, 68056473384187692692674921486), end_range - random.randint(1, 68056473384187692692674921486))

        # Skip if private key has already been used
        if private_key_hex in used_private_keys:
            continue

        used_private_keys.add(private_key_hex)

        # Compute the public key from the private key
        computed_public_key_hex = compute_public_key(private_key_hex, compressed=True)

        #print(f"PrK: {private_key_hex}")
        #print(f"puK: {computed_public_key_hex}")
        #print(f"---: {public_key_hex}")
        #print("-------------------------------------------------------------------------")

        # Compare the computed public key with the given public key
        if computed_public_key_hex == public_key_hex:
            return private_key_hex

def load_used_private_keys():
    """Loads used private keys from a file."""
    used_private_keys = set()
    if os.path.exists(USED_KEYS_FILE):
        with open(USED_KEYS_FILE, "r") as file:
            for line in file:
                used_private_keys.add(line.strip())
    return used_private_keys

def save_all_used_private_keys():
    """Saves all used private keys to a file."""
    with open(USED_KEYS_FILE, "w") as file:
        for key in used_private_keys:
            file.write(key + "\n")

def main():
    """Main function."""
    global used_private_keys
    start_time = time.time()
    try:
        public_key_hex = "02e0a8b039282faf6fe0fd769cfbc4b6b4cf8758ba68220eac420e32b91ddfa673"
        start_range = 2**159  # 0x8000000000000000000000000000000000000000 x = 730750818665451459101842416358141509827966271488
        end_range = 2**160 - 1  # 0xffffffffffffffffffffffffffffffffffffffff y = 1461501637330902918203684832716283019655932542975

        print(f"Searching for private key corresponding to public key: {public_key_hex}")
        print(f" - From: {hex(start_range)}")
        print(f" - To: {hex(end_range)}")

        # Load previously used private keys
        used_private_keys = load_used_private_keys()

        # Register the save function to be called on program exit
        atexit.register(save_all_used_private_keys)

        # Attempt to find the corresponding private key within the specified range
        private_key = find_private_key(public_key_hex, start_range, end_range)
        if private_key:
            print(f"Found private key: {private_key}")
            # Save the found keys to a file
            with open("found_keys.txt", "w") as file:
                file.write(f"Public Key: {public_key_hex}\n")
                file.write(f"Private Key: {private_key}\n")
        else:
            print("Private key not found within the specified range.")
    except KeyboardInterrupt:
        _atime = elapsed_time = time.time() - start_time
        print(f'Stopped after {_atime} seconds')
        print("\nProgram interrupted by user.")

if __name__ == "__main__":
    main()
