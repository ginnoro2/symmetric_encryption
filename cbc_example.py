from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

def encrypt_cbc(plaintext, key):
    """
    Cipher Block Chaining (CBC) Mode
    - Each block is XORed with the previous ciphertext block before encryption
    - First block uses an Initialization Vector (IV)
    - More secure than ECB as it hides patterns
    """
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_text = pad(plaintext.encode(), AES.block_size)
    ciphertext = cipher.encrypt(padded_text)
    # Prepend IV to ciphertext
    return base64.b64encode(iv + ciphertext).decode()

def decrypt_cbc(ciphertext, key):
    ciphertext = base64.b64decode(ciphertext)
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext[AES.block_size:])
    return unpad(decrypted, AES.block_size).decode()

def main():
    # Generate a random 256-bit key
    key = get_random_bytes(32)  # 32 bytes = 256 bits
    
    # Save the key for testing
    with open('cbc_key.txt', 'wb') as f:
        f.write(key)
    
    # Test message with repeating pattern
    message = "You will save this world"  # 20 bytes
    
    print("CBC Mode Example:")
    print("Original Message:", message)
    print("\nNote: Each block is chained with previous block, hiding patterns")
    
    # Encrypt and decrypt
    encrypted = encrypt_cbc(message, key)
    print("\nEncrypted:", encrypted)
    
    decrypted = decrypt_cbc(encrypted, key)
    print("Decrypted:", decrypted)
    
    # Save encrypted message for testing
    with open('cbc_encrypted.txt', 'w') as f:
        f.write(encrypted)
    
    print("\nKey and encrypted message have been saved for testing decryption")
    print("Run cbc_decrypt.py to test decryption")

if __name__ == "__main__":
    main() 