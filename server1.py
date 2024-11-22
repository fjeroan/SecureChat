import socket
import threading

clients = {}  # Store clients as {client_name: connection}

def handle_client(conn, addr):
    """Handle communication with a single client."""
    conn.send(b"Welcome! Enter your name: ")
    client_name = conn.recv(1024).decode().strip()
    clients[client_name] = conn
    conn.send(b"Connected to the chat server.\n")

    while True:
        try:
            # Receive message from client
            message = conn.recv(1024).decode()
            if message.lower() == "exit":
                conn.send(b"Goodbye!\n")
                break
            
            # Send message to a specific client
            if message.startswith("@"):
                target, msg = message[1:].split(" ", 1)
                if target in clients:
                    clients[target].send(f"{client_name}: {msg}".encode())
                else:
                    conn.send(b"User not found.\n")
            else:
                # Broadcast to all clients
                for client, connection in clients.items():
                    if connection != conn:
                        connection.send(f"{client_name}: {message}".encode())
        except:
            break

    # Remove client on disconnect
    del clients[client_name]
    conn.close()

def start_server():
    """Start the chat server."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 12345))
    server.listen(5)
    print("Server is listening...")

    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr)).start()

if __name__ == "__main__":
    start_server()
