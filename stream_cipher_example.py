from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

def encrypt_stream(plaintext, key):
    """
    Stream Cipher Example (using AES in CTR mode)
    - Encrypts data bit by bit or byte by byte
    - Uses a keystream generated from the key
    - Each plaintext bit/byte is XORed with corresponding keystream bit/byte
    - No padding needed
    - Can process data of any length
    """
    nonce = get_random_bytes(8)  # 8 bytes for CTR mode
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    ciphertext = cipher.encrypt(plaintext.encode())
    # Prepend nonce to ciphertext
    return base64.b64encode(nonce + ciphertext).decode()

def decrypt_stream(ciphertext, key):
    ciphertext = base64.b64decode(ciphertext)
    nonce = ciphertext[:8]
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return cipher.decrypt(ciphertext[8:]).decode()

def main():
    # Generate a random 256-bit key
    key = get_random_bytes(32)  # 32 bytes = 256 bits
    
    # Save the key for testing
    with open('stream_key.txt', 'wb') as f:
        f.write(key)
    
    # Test messages of different lengths
    message1 = "Short message"
    message2 = "This is a longer message that demonstrates the flexibility of stream ciphers"
    
    print("Stream Cipher Example (using AES-CTR):")
    print("\nNote: Processes data byte by byte, no padding needed")
    
    # Test with short message
    print("\nShort Message Test:")
    print("Original:", message1)
    encrypted1 = encrypt_stream(message1, key)
    print("Encrypted:", encrypted1)
    decrypted1 = decrypt_stream(encrypted1, key)
    print("Decrypted:", decrypted1)
    
    # Test with longer message
    print("\nLong Message Test:")
    print("Original:", message2)
    encrypted2 = encrypt_stream(message2, key)
    print("Encrypted:", encrypted2)
    decrypted2 = decrypt_stream(encrypted2, key)
    print("Decrypted:", decrypted2)
    
    # Save encrypted messages for testing
    with open('stream_encrypted.txt', 'w') as f:
        f.write(encrypted1 + '\n' + encrypted2)
    
    print("\nKey and encrypted messages have been saved for testing decryption")
    print("Run stream_decrypt.py to test decryption")

if __name__ == "__main__":
    main() 