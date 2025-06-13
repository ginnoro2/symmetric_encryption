from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64

def decrypt_cbc(ciphertext, key):
    """
    Decrypts a message encrypted using CBC mode
    """
    ciphertext = base64.b64decode(ciphertext)
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext[AES.block_size:])
    return unpad(decrypted, AES.block_size).decode()

def main():
    # The key must be the same as used for encryption (hex string)
    key_hex = input("Enter the encryption key (32 bytes in hex format): ")
    key = bytes.fromhex(key_hex)
    
    # Get the encrypted message
    encrypted_message = input("Enter the encrypted message: ")
    
    try:
        # Decrypt the message
        decrypted_message = decrypt_cbc(encrypted_message, key)
        print("\nDecrypted Message:", decrypted_message)
    except Exception as e:
        print("Error during decryption:", str(e))
        print("Make sure you're using the correct key and encrypted message format")

if __name__ == "__main__":
    main() 