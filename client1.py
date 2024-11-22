import socket
import threading

def receive_messages(client):
    """Receive messages from the server."""
    while True:
        try:
            message = client.recv(1024).decode()
            print(message)
        except:
            print("Disconnected from server.")
            break

def start_client():
    """Start the chat client."""
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("127.0.0.1", 12345))

    # Start a thread to receive messages
    threading.Thread(target=receive_messages, args=(client,)).start()

    while True:
        message = input()
        client.send(message.encode())
        if message.lower() == "exit":
            break

    client.close()

if __name__ == "__main__":
    start_client()
