import socket
import threading

# Global dictionaries
clients = {}  # Maps usernames to socket objects
sessions = {}  # Maps usernames to their peer in a session


def handle_client(client_socket, client_address):
    """
    Handles communication with a single client.
    """
    global clients, sessions

    print(f"Connection established with {client_address}")

    # Request username
    client_socket.send("Please enter your username:".encode('utf-8'))
    username = client_socket.recv(1024).decode('utf-8').strip()

    # Ensure the username is unique
    if username in clients:
        client_socket.send("Username already taken. Disconnecting.".encode('utf-8'))
        client_socket.close()
        return

    # Add the client to the list of connected clients
    clients[username] = client_socket
    print(f"Clients connected: {list(clients.keys())}")
    broadcast_client_list()

    # Notify client
    client_socket.send(f"Welcome, {username}! You are now connected.".encode('utf-8'))

    try:
        while True:
            # Receive a message from the client
            message = client_socket.recv(1024).decode('utf-8').strip()
            if not message:
                break

            # Handle commands
            if message.startswith("/startsession"):
                start_private_session(username, message)
            elif message.startswith("/end"):
                end_private_session(username)
            elif message == "/exit":
                break
            else:
                route_message(username, message)

    except Exception as e:
        print(f"Error with client {username}: {e}")
    finally:
        # Cleanup on disconnect
        disconnect_client(username)
        client_socket.close()


def start_private_session(sender, message):
    """
    Starts a private session between two users.
    """
    global sessions

    # Parse the target username
    parts = message.split(" ", 1)
    if len(parts) < 2:
        clients[sender].send("Usage: /startsession <username>".encode('utf-8'))
        return

    target = parts[1]

    if target not in clients:
        clients[sender].send(f"User {target} is not connected.".encode('utf-8'))
        return

    if sender in sessions or target in sessions:
        clients[sender].send("One of you is already in a session.".encode('utf-8'))
        return

    # Establish the session
    sessions[sender] = target
    sessions[target] = sender
    clients[sender].send(f"Private session started with {target}.".encode('utf-8'))
    clients[target].send(f"Private session started with {sender}.".encode('utf-8'))


def end_private_session(username):
    """
    Ends a private session for the given user.
    """
    global sessions

    if username in sessions:
        peer = sessions.pop(username)
        sessions.pop(peer, None)

        clients[username].send("Private session ended.".encode('utf-8'))
        clients[peer].send("Private session ended.".encode('utf-8'))


def route_message(sender, message):
    """
    Routes a message either to the peer in a private session or broadcasts it.
    """
    if sender in sessions:
        # Send to the peer in the private session
        peer = sessions[sender]
        if peer in clients:
            try:
                clients[peer].send(f"[Private] {sender}: {message}".encode('utf-8'))
            except Exception as e:
                print(f"Error sending private message to {peer}: {e}")
                end_private_session(sender)
        else:
            clients[sender].send("Your peer has disconnected.".encode('utf-8'))
            end_private_session(sender)
    else:
        # Broadcast to all clients
        broadcast_message(f"{sender}: {message}", exclude=sender)


def broadcast_message(message, exclude=None):
    """
    Sends a message to all connected clients except the excluded one.
    """
    for user, client in clients.items():
        if user != exclude:
            try:
                client.send(message.encode('utf-8'))
            except Exception as e:
                print(f"Error broadcasting to {user}: {e}")


def broadcast_client_list():
    """
    Sends an updated list of connected clients to all clients.
    """
    client_list = list(clients.keys())
    message = f"Updated client list: {client_list}"
    for client in clients.values():
        try:
            client.send(message.encode('utf-8'))
        except Exception as e:
            print(f"Error broadcasting client list: {e}")


def disconnect_client(username):
    """
    Handles client disconnection.
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
    Starts the server and listens for incoming connections.
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('127.0.0.1', 12345))
    server_socket.listen(5)
    print("Server is running on 127.0.0.1:12345...")

    try:
        while True:
            client_socket, client_address = server_socket.accept()
            threading.Thread(target=handle_client, args=(client_socket, client_address)).start()
    except KeyboardInterrupt:
        print("\nServer is shutting down...")
        server_socket.close()


if __name__ == "__main__":
    start_server()
