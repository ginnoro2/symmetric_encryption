from Crypto.Cipher import AES
import base64

def decrypt_stream(ciphertext, key):
    """
    Decrypts a message encrypted using stream cipher (AES-CTR mode)
    """
    ciphertext = base64.b64decode(ciphertext)
    nonce = ciphertext[:8]
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return cipher.decrypt(ciphertext[8:]).decode()

def main():
    # The key must be the same as used for encryption (hex string)
    key_hex = input("Enter the encryption key (32 bytes in hex format): ")
    key = bytes.fromhex(key_hex)
    
    # Get the encrypted message
    encrypted_message = input("Enter the encrypted message: ")
    
    try:
        # Decrypt the message
        decrypted_message = decrypt_stream(encrypted_message, key)
        print("\nDecrypted Message:", decrypted_message)
    except Exception as e:
        print("Error during decryption:", str(e))
        print("Make sure you're using the correct key and encrypted message format")

if __name__ == "__main__":
    main() 