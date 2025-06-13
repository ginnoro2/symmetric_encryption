from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

def encrypt_ecb(plaintext, key):
    """
    Electronic Codebook (ECB) Mode
    - Each block is encrypted independently
    - Same plaintext blocks produce same ciphertext blocks
    - Vulnerable to pattern analysis
    """
    cipher = AES.new(key, AES.MODE_ECB)
    padded_text = pad(plaintext.encode(), AES.block_size)
    ciphertext = cipher.encrypt(padded_text)
    return base64.b64encode(ciphertext).decode()

def decrypt_ecb(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(base64.b64decode(ciphertext))
    return unpad(decrypted, AES.block_size).decode()

def main():
    # Generate a random 256-bit key
    key = get_random_bytes(32)  # 32 bytes = 256 bits
    
    # Save the key for testing
    with open('ecb_key.txt', 'wb') as f:
        f.write(key)
    
    # Test message with repeating pattern to demonstrate ECB weakness
    message = "You are Ethical Hackers"  # 20 bytes, will show pattern in ECB
    
    print("ECB Mode Example:")
    print("Original Message:", message)
    print("\nNote: Same blocks produce same ciphertext, making patterns visible")
    
    # Encrypt and decrypt
    encrypted = encrypt_ecb(message, key)
    print("\nEncrypted:", encrypted)
    
    decrypted = decrypt_ecb(encrypted, key)
    print("Decrypted:", decrypted)
    
    # Save encrypted message for testing
    with open('ecb_encrypted.txt', 'w') as f:
        f.write(encrypted)
    
    print("\nKey and encrypted message have been saved for testing decryption")
    print("Run ecb_decrypt.py to test decryption")

if __name__ == "__main__":
    main() 