import hashlib
from PIL import Image
import numpy as np
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

def encrypt_message(message, key):
    # Generate a 32-byte key from the password using SHA-256
    key_bytes = hashlib.sha256(key.encode()).digest()
    
    # Generate a random IV
    iv = get_random_bytes(AES.block_size)
    
    # Create cipher and encrypt
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(message.encode(), AES.block_size))
    
    # Convert to base64 for safe string handling
    return base64.b64encode(encrypted).decode(), base64.b64encode(iv).decode()

def decrypt_message(encrypted_message, iv, key):
    # Generate the same key from password
    key_bytes = hashlib.sha256(key.encode()).digest()
    
    # Decode base64
    encrypted = base64.b64decode(encrypted_message)
    iv_bytes = base64.b64decode(iv)
    
    # Create cipher and decrypt
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
    decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)
    
    return decrypted.decode()

def embed_message_in_image(cover_path, stego_path, message, key):
    # First encrypt the message
    encrypted_message, iv = encrypt_message(message, key)
    
    # Combine IV and encrypted message with a delimiter
    full_message = f"{iv}:{encrypted_message}"
    
    img = Image.open(cover_path)
    pixels = np.array(img)
    m, n = pixels.shape[0], pixels.shape[1]
    if n < 54:
        raise ValueError("Image width must be at least 54 pixels for SHA1 hash storage (min 54 pixels)")
    
    # 1. Store SHA1(key) in first row (160 bits)
    sha1 = hashlib.sha1(key.encode()).digest()
    hash_bits = ''.join(f"{byte:08b}" for byte in sha1)
    row = 0
    col = 0
    channel = 0
    key_idx = 0
    for bit in hash_bits:
        k = ord(key[key_idx % len(key)]) % 2  # 0 or 1
        key_idx += 1
        # Set the k-th LSB of this pixel channel
        pixel = int(pixels[row, col][channel])
        pixel = (pixel & ~(1 << k)) | (int(bit) << k)
        pixels[row, col][channel] = pixel
        channel += 1
        if channel == 3:
            channel = 0
            col += 1
            if col == n:
                break  # Shouldn't happen if n >= 54
    
    # 2. Calculate bit plane from key
    key_sum = sum(ord(c) for c in key)
    bit_plane = (key_sum % 8) + 1  # 1-8
    
    # 3. Store bit plane info in first pixel of second row
    row = 1
    col = 0
    channel = 0
    pixel = int(pixels[row, col][channel])
    pixel = (pixel & ~(0b111 << 1)) | ((bit_plane - 1) << 1)  # Store bit plane in bits 1-3
    pixels[row, col][channel] = pixel
    
    # 4. Embed message (as bits) from second pixel of second row, with null char at end
    message_bits = ''.join(f"{ord(c):08b}" for c in full_message) + '00000000'  # null char
    col = 1  # Start from second pixel
    channel = 0
    key_idx = 0
    for bit in message_bits:
        k = ord(key[key_idx % len(key)]) % 2
        key_idx += 1
        pixel = int(pixels[row, col][channel])
        # Clear the target bit plane
        pixel = pixel & ~(1 << (bit_plane - 1))
        # Set the bit in the target plane
        pixel = pixel | (int(bit) << (bit_plane - 1))
        pixels[row, col][channel] = pixel
        channel += 1
        if channel == 3:
            channel = 0
            col += 1
            if col == n:
                col = 0
                row += 1
                if row == m:
                    raise ValueError("Image too small for message!")
    Image.fromarray(pixels).save(stego_path)

def extract_message_from_image(stego_path, key):
    img = Image.open(stego_path)
    pixels = np.array(img)
    m, n = pixels.shape[0], pixels.shape[1]
    
    # 1. Extract SHA1(key) from first row
    bits = []
    row = 0
    col = 0
    channel = 0
    key_idx = 0
    for _ in range(160):
        k = ord(key[key_idx % len(key)]) % 2
        key_idx += 1
        pixel = int(pixels[row, col][channel])
        bits.append(str((pixel >> k) & 1))
        channel += 1
        if channel == 3:
            channel = 0
            col += 1
    hash_bits = ''.join(bits)
    sha1 = hashlib.sha1(key.encode()).digest()
    expected_hash_bits = ''.join(f"{byte:08b}" for byte in sha1)
    if hash_bits != expected_hash_bits:
        raise ValueError("Password mismatch or not a Photocrypt stego image!")
    
    # 2. Extract bit plane info from first pixel of second row
    row = 1
    col = 0
    channel = 0
    pixel = int(pixels[row, col][channel])
    bit_plane = ((pixel >> 1) & 0b111) + 1  # Extract bits 1-3 and add 1
    
    # 3. Extract message bits from second pixel of second row
    bits = []
    col = 1  # Start from second pixel
    channel = 0
    key_idx = 0
    zeroes = 0
    while True:
        k = ord(key[key_idx % len(key)]) % 2
        key_idx += 1
        pixel = int(pixels[row, col][channel])
        bit = (pixel >> (bit_plane - 1)) & 1
        bits.append(str(bit))
        if bit == 0:
            zeroes += 1
        else:
            zeroes = 0
        if zeroes == 8:  # Found null terminator
            break
        channel += 1
        if channel == 3:
            channel = 0
            col += 1
            if col == n:
                col = 0
                row += 1
                if row == m:
                    break
    
    # Convert bits to string, excluding the null terminator
    message_bits = bits[:-8]  # Remove the null terminator bits
    
    # Convert bits to characters
    chars = []
    for i in range(0, len(message_bits), 8):
        if i + 8 <= len(message_bits):  # Ensure we have a complete byte
            byte = message_bits[i:i+8]
            chars.append(chr(int(''.join(byte), 2)))
    
    # Split the extracted string into IV and encrypted message
    full_message = ''.join(chars)
    try:
        iv, encrypted_message = full_message.split(':')
        # Decrypt the message
        return decrypt_message(encrypted_message, iv, key)
    except ValueError:
        raise ValueError("Failed to decrypt message - invalid format or wrong password")

if __name__ == "__main__":
    cover = "mountain.png"
    stego = "stego.png"
    secret = "Hello, Photocrypt!"
    password = "mysecretkey"
    print(f"Embedding: '{secret}' with key '{password}'...")
    embed_message_in_image(cover, stego, secret, password)
    print(f"Extracting with key '{password}'...")
    result = extract_message_from_image(stego, password)
    print(f"Extracted: '{result}'")
    print(f"Success: {result == secret}") 