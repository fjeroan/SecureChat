from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hmac
import hashlib
import socket
import threading
import os

# RSA key pair generation for client
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Serialize the public key
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Use global variables for session and HMAC keys
SESSION_KEY = None
HMAC_KEY = None
BLOCK_SIZE = 16
received_nonces = set()  # To track received nonces


def encrypt_message(plaintext):
    """
    Encrypts a message using the session key and HMAC key.
    """
    global SESSION_KEY, HMAC_KEY

    if not SESSION_KEY or not HMAC_KEY:
        raise ValueError("Session keys are not established.")

    # Generate random IV and nonce
    iv = os.urandom(BLOCK_SIZE)
    nonce = os.urandom(16)  # 16-byte nonce

    # Append nonce to the plaintext message
    plaintext_with_nonce = plaintext.encode('utf-8') + nonce

    # Compute HMAC over the message + nonce
    hmac_value = hmac.new(HMAC_KEY, plaintext_with_nonce, hashlib.sha256).digest()

    # Combine plaintext, nonce, and HMAC
    data_to_encrypt = plaintext_with_nonce + hmac_value

    # Encrypt using AES-CBC
    cipher = AES.new(SESSION_KEY, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data_to_encrypt, BLOCK_SIZE))

    # Return IV + ciphertext
    return iv + ciphertext



def decrypt_message(encrypted_message):
    """
    Decrypts a message using the session key and HMAC key.
    """
    global SESSION_KEY, HMAC_KEY

    if not SESSION_KEY or not HMAC_KEY:
        raise ValueError("Session keys are not established.")

    # Split IV and ciphertext
    iv = encrypted_message[:BLOCK_SIZE]
    ciphertext = encrypted_message[BLOCK_SIZE:]

    # Decrypt using AES-CBC
    cipher = AES.new(SESSION_KEY, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(ciphertext), BLOCK_SIZE)

    # Split message, nonce, and HMAC
    plaintext_with_nonce = decrypted_data[:-32]  # Last 32 bytes is HMAC
    received_hmac = decrypted_data[-32:]        # Extract the received HMAC

    # Extract the nonce from the plaintext
    plaintext = plaintext_with_nonce[:-16]  # Last 16 bytes are nonce
    nonce = plaintext_with_nonce[-16:]      # Extract nonce

    # Verify integrity using HMAC
    expected_hmac = hmac.new(HMAC_KEY, plaintext_with_nonce, hashlib.sha256).digest()
    if not hmac.compare_digest(received_hmac, expected_hmac):
        raise ValueError("Integrity check failed! HMAC does not match.")

    return plaintext.decode('utf-8')



def authenticate(client_socket, username):
    """
    Authenticates the client with the server and sends the client's public key.
    """
    try:
        # Step 1: Receive the server's public key
        public_key_pem_server = client_socket.recv(2048)
        print(f"Server's public key received: {public_key_pem_server}")  # Debugging

        # Load the server's public key
        server_public_key = serialization.load_pem_public_key(public_key_pem_server)

        # Step 2: Create an authentication token
        auth_token = f"{username}_{os.urandom(16).hex()}".encode()
        print(f"Generated authentication token: {auth_token}")  # Debugging

        # Step 3: Encrypt the token with the server's public key
        encrypted_token = server_public_key.encrypt(
            auth_token,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(f"Encrypted authentication token: {encrypted_token}")  # Debugging

        # Step 4: Send the encrypted token to the server
        client_socket.send(encrypted_token)
        print("Authentication token sent to the server.")  # Debugging

        # Step 5: Send the client's public key to the server
        client_socket.send(public_key_pem)
        print("Client's public key sent to the server.")  # Debugging

        # Step 6: Wait for the server's authentication response
        response = client_socket.recv(1024).decode('utf-8').strip()
        print(f"Authentication response from server: {response}")  # Debugging

        return response == "AUTH_SUCCESS"
    except Exception as e:
        print(f"Error during authentication: {e}")
        return False




def receive_messages(client_socket):
    global SESSION_KEY, HMAC_KEY

    while True:
        try:
            data = client_socket.recv(2048)
            if not data:
                print("Server has closed the connection.")
                break

            # Handle session key distribution (with "KEY:" prefix)
            if data.startswith(b"KEY:"):
                # Extract the encrypted key data (remove the "KEY:" prefix)
                encrypted_key_data = data[4:]
                try:
                    # Decrypt the session key and HMAC key using client's private key
                    key_data = private_key.decrypt(
                        encrypted_key_data,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    # Split the decrypted data into session key and HMAC key
                    SESSION_KEY = key_data[:16]  # The first 16 bytes for the AES key
                    HMAC_KEY = key_data[16:48]   # The next 32 bytes for the HMAC key
                    print("Session keys successfully established!")
                except Exception as e:
                    print(f"Error decrypting session keys: {e}")

            # Handle encrypted private messages (with "MSG:" prefix)
            elif data.startswith(b"MSG:"):
                if SESSION_KEY and HMAC_KEY:
                    encrypted_message = data[4:]  # Remove "MSG:" prefix
                    try:
                        message = decrypt_message(encrypted_message)
                        print(f"\n[Private] {message}\n")  # No need to decode here, already decoded
                    except Exception as e:
                        print(f"Error decrypting message: {e}")
                else:
                    print("Session keys are not established.")
            else:
                # Handle regular text commands or other messages
                print(data.decode('utf-8'))  # Decode as UTF-8 if it's a normal message
        except Exception as e:
            print(f"Error receiving message: {e}")
            break
    client_socket.close()








def start_client():
    print("Starting client...")  # Debugging
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', 12345))
    print("Connected to the server.")  # Debugging

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
            if message.startswith("/"):
                # Send commands like /startsession and /help as plaintext
                print(f"Sending command: {message}")  # Debugging
                client_socket.send(message.encode('utf-8'))
            else:
                # Encrypt regular messages with session keys and HMAC keys
                if SESSION_KEY and HMAC_KEY:
                    encrypted_message = encrypt_message(message)

                    # Debugging: Log the encrypted message
                    print(f"Encrypted message to send: {encrypted_message}")

                    # Send the encrypted message with a prefix "MSG:" indicating it's a message
                    client_socket.send(b"MSG:" + encrypted_message)
                else:
                    print("Session keys not established. Message not sent.")
        except Exception as e:
            print(f"Error sending message: {e}")

    client_socket.close()


if _name_ == "_main_":
    start_client()