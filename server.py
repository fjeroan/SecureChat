import socket
import threading
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Global mappings
clients = {}
sessions = {}

# RSA key generation
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

public_key = private_key.public_key()

# Serializing public key
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

#Authenticates client
def authenticate_client(client_socket):

    try:
        # Send the public key to the client
        client_socket.send(public_key_pem)

        # Receive the encrypted token from the client
        encrypted_token = client_socket.recv(1024)

        # Decrypt the token
        decrypted_token = private_key.decrypt(
            encrypted_token,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Extracting the username
        username = decrypted_token.decode('utf-8').split('_')[0]
        print(f"Client {username} authenticated successfully.")
        return username
    except Exception as e:
        print(f"Authentication failed: {e}")
        client_socket.send("AUTH_FAILURE".encode())
        return None

#handles client communication
def handle_client(client_socket, client_address):

    global clients, sessions

    print(f"Connection established with {client_address}")

    # Authenticating the client
    username = authenticate_client(client_socket)
    if not username:
        client_socket.close()
        return

    # Adding the client to the connected clients list
    clients[username] = client_socket
    client_socket.send("AUTH_SUCCESS".encode())
    print(f"Clients connected: {list(clients.keys())}")
    broadcast_client_list()

    client_socket.send(f"\nWelcome, {username}! Type /help for commands.".encode())

    try:
        while True:
            message = client_socket.recv(1024).decode('utf-8').strip()
            if not message:
                break

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
                                   "/exit - Disconnect".encode())
            elif message.startswith("/list"):
                broadcast_client_list()
            else:
                route_message(username, message)
    except Exception as e:
        print(f"Error handling client {username}: {e}")
    finally:
        disconnect_client(username)
        client_socket.close()

#starting a private session
def start_private_session(sender, message):

    global sessions

    parts = message.split(" ", 1)
    if len(parts) < 2:
        clients[sender].send("Usage: /startsession <username>".encode())
        return

    target = parts[1]
    if target not in clients:
        clients[sender].send(f"User {target} is not connected.".encode())
        return

    if sender in sessions or target in sessions:
        clients[sender].send("One of you is already in a session.".encode())
        return

    sessions[sender] = target
    sessions[target] = sender
    clients[sender].send(f"Private session started with {target}.".encode())
    clients[target].send(f"Private session started with {sender}.".encode())

#ends a private session
def end_private_session(username):
 
    global sessions

    if username in sessions:
        peer = sessions.pop(username)
        sessions.pop(peer, None)

        clients[username].send("Private session ended.".encode())
        clients[peer].send("Private session ended.".encode())

#sends message to the correct client
def route_message(sender, message):

    if sender in sessions:
        peer = sessions[sender]
        if peer in clients:
            clients[peer].send(f"[Private] {sender}: {message}".encode())
        else:
            clients[sender].send("Your peer has disconnected.".encode())
            end_private_session(sender)
    else:
        broadcast_message(f"{sender}: {message}", exclude=sender)

#serds message to all clientsd
def broadcast_message(message, exclude=None):

    for user, client in clients.items():
        if user != exclude:
            client.send(message.encode())

#send clientg list to all clients
def broadcast_client_list():

    client_list = list(clients.keys())
    message = f"Connected clients: {client_list}"
    for client in clients.values():
        client.send(message.encode())

#disconnects a client
def disconnect_client(username):
    """
    Handles a client disconnecting.
    """
    global clients, sessions

    if username in clients:
        del clients[username]

    if username in sessions:
        end_private_session(username)

    broadcast_client_list()
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
        client_socket, client_address = server_socket.accept()
        threading.Thread(target=handle_client, args=(client_socket, client_address)).start()


if __name__ == "__main__":
    start_server()