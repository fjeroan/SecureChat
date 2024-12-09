import socket
import threading
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hmac
import hashlib
import os

# Global mappings
clients = []
sessions = []
public_keys = {}

# RSA key generation for server
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

public_key = private_key.public_key()

# Serialize public key for sending to clients
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

def handle_client(client_socket, client_address):
    global clients, sessions, public_keys

    print(f"Connection established with {client_address}")

    # Send the server's public key to the client
    client_socket.send(public_key_pem)

    # Authenticate the client (no server authentication)
    username = authenticate_client(client_socket)
    if not username:
        client_socket.close()
        return

    # Add the client to the list of connected clients
    if username not in clients:
        clients.append(username)
    print(f"Clients connected: {clients}")
    # Broadcast the new client joining the server
    broadcast_message(f"{username} has joined the server!", exclude=username)

    broadcast_client_list()

    client_socket.send(f"Welcome, {username}! Type /help for commands.".encode('utf-8'))

    try:
        while True:
            data = client_socket.recv(2048)
            print(f"Received data: {data}")  # Debugging: Log the received data
            if not data:
                break
            message = data.decode('utf-8').strip()

            if message.startswith("/startsession"):
                start_private_session(username, message)
            elif message.startswith("/end"):
                end_private_session(username)
            elif message == "/exit":
                break
            elif message.startswith("/help"):
                client_socket.send("/startsession <username> - Start a private session\n"
                                   "/end - End a private session\n"
                                   "/list - List connected clients\n"
                                   "/exit - Disconnect".encode('utf-8'))
            elif message.startswith("/list"):
                broadcast_client_list()
            else:
                route_message(username, message)
    except Exception as e:
        print(f"Error handling client {username}: {e}")
    finally:
        disconnect_client(username)
        client_socket.close()


def authenticate_client(client_socket):
    """
    Authenticates a client using RSA and registers their public key.
    """
    global public_keys  # Ensure we access the global dictionary for storing public keys

    try:
        # Step 1: Receive the encrypted token from the client
        encrypted_token = client_socket.recv(1024)
        print(f"Encrypted token received: {encrypted_token}")  # Debugging

        # Step 2: Decrypt the token using the server's private key
        decrypted_token = private_key.decrypt(
            encrypted_token,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(f"Decrypted token: {decrypted_token.decode('utf-8')}")  # Debugging

        # Step 3: Extract the username from the decrypted token
        username = decrypted_token.decode('utf-8').split('_')[0]
        print(f"Authenticated username: {username}")

        # Step 4: Receive the client's public key
        client_public_key_pem = client_socket.recv(2048)
        print(f"Public key PEM received for {username}: {client_public_key_pem}")  # Debugging
        client_public_key = serialization.load_pem_public_key(client_public_key_pem)

        # Step 5: Register the client's public key
        public_keys[username] = client_public_key
        print(f"Registered public key for {username}.")

        # Step 6: Send authentication success message to the client
        client_socket.send("AUTH_SUCCESS".encode('utf-8'))
        return username
    except Exception as e:
        print(f"Authentication failed: {e}")
        client_socket.send("AUTH_FAILURE".encode('utf-8'))
        return None




def start_private_session(sender, message):
    """
    Starts a private session between two users.
    """
    global sessions, clients

    parts = message.split(" ", 1)
    if len(parts) < 2:
        print(f"Usage: /startsession <username>")
        return

    target = parts[1]
    if target not in clients:
        print(f"User {target} is not connected.")
        return

    # Check if sender or target are already in a session
    if any(sender in session or target in session for session in sessions):
        print(f"One of you is already in a session.")
        return

    # Remove both sender and target from the clients list
    clients.remove(sender)
    clients.remove(target)

    # Add the users to the sessions list as a tuple
    sessions.append((sender, target))

    print(f"Private session established between {sender} and {target}.")

    # Generate symmetric session key and HMAC key
    session_key = os.urandom(16)  # 16-byte AES key
    hmac_key = os.urandom(32)    # 32-byte HMAC key
    key_data = session_key + hmac_key

    # Encrypt the keys for both clients
    encrypted_for_sender = public_keys[sender].encrypt(
        key_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    encrypted_for_target = public_keys[target].encrypt(
        key_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Send encrypted keys to both clients with "KEY:" prefix
    clients[sender].send(b"KEY:" + encrypted_for_sender)
    clients[target].send(b"KEY:" + encrypted_for_target)

    print(f"Private session established between {sender} and {target}.")

    print(f"Private session established between {sender} and {target}.")






def end_private_session(username):
    """
    Ends a private session for a user and adds them back to the clients list.
    """
    global sessions, clients

    # Find and remove the session for the username
    session = next((s for s in sessions if username in s), None)
    if session:
        # Remove session from sessions
        sessions.remove(session)

        # The other peer in the session
        peer = session[1] if session[0] == username else session[0]

        # Add both back to clients
        if username not in clients:
            clients.append(username)
        if peer not in clients:
            clients.append(peer)

        print(f"Private session ended between {username} and {peer}.")






def route_message(sender, message):
    """
    Routes a message to the intended recipient(s).
    """
    if sender in sessions:
        peer = sessions[sender]
        if peer in clients:
            try:
                # Simply forward the message to the peer
                clients[peer].send(message.encode('utf-8'))
            except Exception as e:
                print(f"Error sending private message to {peer}: {e}")
                end_private_session(sender)
        else:
            clients[sender].send("Your peer has disconnected.".encode())
            end_private_session(sender)
    else:
        # Broadcast to all clients if no private session
        broadcast_message(f"{sender}: {message}", exclude=sender)




def broadcast_message(message, exclude=None):
    """
    Broadcasts a message to all clients except the excluded one.
    """
    for user, client in clients.items():
        if user != exclude:
            client.send(message.encode())


def broadcast_client_list():
    """
    Sends an updated list of connected clients to all clients.
    """
    message = f"Connected clients: {clients}"  # clients is now a list of usernames
    for client in clients:
        print(message)  # Debugging: display the broadcast message



def disconnect_client(username):
    """
    Handles a client disconnecting.
    """
    global clients, sessions

    # Remove the client from the clients list
    if username in clients:
        clients.remove(username)

    # End any session the client is involved in
    if username in [u for session in sessions for u in session]:  # Flatten sessions
        end_private_session(username)

    # Notify all clients that the user has left
    broadcast_message(f"{username} has left the server.")

    print(f"{username} disconnected.")



def start_server():
    """
    Starts the server and listens for client connections.
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('127.0.0.1', 12345))
    server_socket.listen(5)
    print("Server is running on 127.0.0.1:12345...")

    while True:
        print("Waiting for client connections...")  # Debugging: Check if the server is waiting for connections
        client_socket, client_address = server_socket.accept()
        print(f"Connection established with {client_address}")  # Debugging: Confirm when a connection is established
        threading.Thread(target=handle_client, args=(client_socket, client_address)).start()


if _name_ == "_main_":
    start_server()