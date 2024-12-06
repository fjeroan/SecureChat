
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
import socket
import threading
import os


from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hmac
import hashlib


private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Serialize the public key
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)


#SESSION_KEY = None
#HMAC_KEY = None

# AES block size
BLOCK_SIZE = 16


def encrypt_message(plaintext, SESSION_KEY, HMAC_KEY):
    # Generate random IV and noise
    iv = os.urandom(BLOCK_SIZE)
    noise = os.urandom(8)

    # Mix plaintext with random noise
    plaintext_with_noise = plaintext.encode('utf-8') + noise

    # Encrypt using AES-CBC
    cipher = AES.new(SESSION_KEY, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext_with_noise, BLOCK_SIZE))

    # Compute HMAC for the encrypted message
    hmac_value = hmac.new(HMAC_KEY, iv + ciphertext, hashlib.sha256).digest()

    # Return the IV, ciphertext, and HMAC
    return iv + ciphertext + hmac_value


def decrypt_message(encrypted_message, SESSION_KEY, HMAC_KEY):
    # Split the IV, ciphertext, and HMAC
    iv = encrypted_message[:BLOCK_SIZE]
    ciphertext = encrypted_message[BLOCK_SIZE:-32]
    received_hmac = encrypted_message[-32:]

    # Verify HMAC
    expected_hmac = hmac.new(HMAC_KEY, iv + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(expected_hmac, received_hmac):
        raise ValueError("Integrity check failed! HMAC does not match.")

    # Decrypt using AES-CBC
    cipher = AES.new(SESSION_KEY, AES.MODE_CBC, iv)
    plaintext_with_noise = unpad(cipher.decrypt(ciphertext), BLOCK_SIZE)

    # Separate plaintext from noise
    plaintext = plaintext_with_noise[:-8]  # Remove the last 8 bytes (noise)
    return plaintext.decode('utf-8')


def receive_messages(client_socket):
    global SESSION_KEY, HMAC_KEY

    while True:
        try:
            encrypted_message = client_socket.recv(1024)
            if encrypted_message:
                # Decrypt the session keys if they are part of the message
                try:
                    key_data = private_key.decrypt(
                        encrypted_message,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    SESSION_KEY = key_data[:16]
                    HMAC_KEY = key_data[16:48]
                    print("Session and HMAC keys received and decrypted!")
                except Exception as e:
                    # Handle regular encrypted messages
                    if SESSION_KEY and HMAC_KEY:
                        message = decrypt_message(encrypted_message, SESSION_KEY, HMAC_KEY)
                        print(f"\n{message}\n")
                    else:
                        print(f"Failed to decrypt message: {e}")
            else:
                print("Server has closed the connection.")
                break
        except Exception as e:
            print(f"Error receiving message: {e}")
            break
    client_socket.close()



def authenticate(client_socket, username):
    # Receive server's public key
    public_key_pem_server = client_socket.recv(1024)
    server_public_key = serialization.load_pem_public_key(public_key_pem_server)
    print(server_public_key)

    # Create an authentication token
    auth_token = f"{username}_{os.urandom(16).hex()}".encode()

    # Encrypt the token with the server's public key
    encrypted_token = server_public_key.encrypt(
        auth_token,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Send the encrypted token and public key
    client_socket.send(encrypted_token)
    client_socket.send(public_key_pem)

    # Wait for the authentication response
    response = client_socket.recv(1024).decode()
    if response == "AUTH_SUCCESS":
        print("Authenticated successfully!")
        return True
    else:
        print("Authentication failed.")
        return False


   








def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', 12345))

    username = input("Enter your username: ")
    if authenticate(client_socket, username):
        print("Authenticated successfully!")
    else:
        print("Authentication failed. Disconnecting...")
        client_socket.close()
        return

    threading.Thread(target=receive_messages, args=(client_socket,), daemon=True).start()

    while True:
        message = input()
        if message.lower() == 'exit':
            break
        try:
            # encrypted_message = encrypt_message(message, SESSION_KEY, HMAC_KEY)
            # client_socket.send(encrypted_message)
            client_socket.send(message.encode('utf-8'))
        except Exception as e:
            print(f"Error sending message: {e}")

    client_socket.close()


if __name__ == "__main__":
    start_client()