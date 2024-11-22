import socket
import threading

# Constants
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 12345
BUFFER_SIZE = 1024

# List of connected clients
clients = {}
client_threads = []

# Function to handle client communication
def handle_client(client_socket, client_address):
    client_name = client_socket.recv(BUFFER_SIZE).decode()
    clients[client_name] = client_socket
    print(f"[INFO] {client_name} connected from {client_address}.")

    try:
        while True:
            # Receive a message from the client
            message = client_socket.recv(BUFFER_SIZE).decode()
            if not message:
                break

            print(f"[MESSAGE] {client_name}: {message}")

            # Broadcast to the intended recipient
            if message.startswith("@"):
                recipient, msg = message[1:].split(" ", 1)
                if recipient in clients:
                    clients[recipient].send(f"{client_name}: {msg}".encode())
                else:
                    client_socket.send("[ERROR] Recipient not found.".encode())
            else:
                client_socket.send("[ERROR] Invalid format. Use @recipient message.".encode())
    except ConnectionError:
        print(f"[INFO] {client_name} disconnected.")
    finally:
        client_socket.close()
        del clients[client_name]

# Main server function
def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_HOST, SERVER_PORT))
    server_socket.listen(5)
    print(f"[INFO] Server started on {SERVER_HOST}:{SERVER_PORT}")

    try:
        while True:
            client_socket, client_address = server_socket.accept()
            client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
            client_threads.append(client_thread)
            client_thread.start()
    except KeyboardInterrupt:
        print("[INFO] Server shutting down...")
    finally:
        server_socket.close()

if __name__ == "__main__":
    start_server()
