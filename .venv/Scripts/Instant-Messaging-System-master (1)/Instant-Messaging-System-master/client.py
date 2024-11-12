# Pradeepa Shri Jothinathan - 1001241839
import socket
import select
import random
import time
import os
import platform
import sys
import headers as h

flag = 0
name = ''
RECV_BUFF = 4096


def chat_client():
     # The host name and port of the server given as command line arguments
    if len(sys.argv) < 3:
        print('Usage : python3 client.py hostname port')
        print('Port: 6000')
        sys.exit()
    host = sys.argv[1]
    port = int(sys.argv[2])
    name = ""
    name2 = ""
    flag = 0
    add, cl, s = server_client_connect()

    # connect to server
    try:
        s.connect((host, port))
        print("Please wait while service loads...\n")
    except IOError as e:
        print('Unable to connect')
        print(e)
        sys.exit()

    socket_list = [sys.stdin, s, cl]
    # while loop to repeatedly check for the data
    while True:
        ready_to_read, ready_to_write, in_error = select.select(socket_list, [], [])

        for sock in ready_to_read:
            # If connection from server
            if sock == s:
                data = sock.recv(RECV_BUFF)
                data = data.decode()
                if not data:
                # if there is no data, disconnect from server
                    print('\nDisconnected from chat server')
                    sys.exit()
                else:
                    # If client receives client info from the server
                    if "CONNECT" in data:
                    # if the server sends connection acceptance between two clients, connect them using connect()
                        data = find_between(data, "<", ">")
                        data, host, port = get_host_port(data)
                        cs, flag = connect(flag, host, name, name2, port, s, socket_list)
                    # if server sends online user information
                    if "ONLINE" in data:
                        if platform.system() == 'Darwin':
                            os.system('clear')
                            # print_help()
                        elif platform.system() == 'Windows':
                            os.system('cls')
                            print_help()
                        print(data + "\n")
                    # if server accepts a client connection, client registers with a username
                    if data == "connection":
                        while True:
                            username = input("Enter Username: ")
                            name = username
                            s.send(username.encode())
                            x = s.recv(RECV_BUFF)
                            x = x.decode()
                            if x == "False":
                                print("Sorry, username already in use")
                            else:
                                time.sleep(0.2)
                                print('\nConnected to the Server\n')
                                print_help()
                                s.send(str(add).encode())
                                break
                        break
                    # if server sends connection rejection information
                    if "Requested user is already chatting" in data or "Requested user is not available" in data:
                        print(data)
            # If connection is on client listening socket
            # Accept the client connection
            elif sock == cl:
                client, address = sock.accept()
                socket_list.append(client)
                flag = 2
            # If there is a keyboard input
            elif sock == sys.stdin:
                msg = sys.stdin.readline()
                if "LOGOFF" in msg:
                # disconnect the client if key board input is LOGOFF
                    s.send((msg + "<" + name + ">" + h.LOGOFF_GET_MSG).encode())
                    data = s.recv(RECV_BUFF).decode()
                    print(data)
                    sys.exit()
                elif "ONLINE" in msg:
                # show online users
                    s.send(h.ONLINE_GET_MSG.encode())
                # If client needs help with service usage
                elif "HELP" in msg:
                    print_help()
                else:
                    # if a client wants to make a connection
                    if "CONNECT" in msg:
                        name2 = find_between(msg, "<", ">")

                    if flag == 1:
                        cs.send((name + ": " + msg).encode())
                    elif flag == 2:
                        client.send((name + ": " + msg).encode())
                    else:
                        if "CONNECT" in msg:
                            name2 = find_between(msg, "<", ">")
                            if name2 == name:
                                print("Cannot connect to yourself")
                            else:
                                s.send((msg + h.CONNECT_GET_MSG).encode())
                        else:
                            s.send(msg.encode())
            else:
                # if connection is on the client receiving socket
                data = sock.recv(RECV_BUFF)
                data = data.decode()
                
                if not data:
                # if there is no data, disconnect from the server
                    print('\nDisconnected from chat server')
                    sys.exit()
                else:
                    # if client notifies to end the chat
                    if "END" in data:
                        print("Your session has been closed\n")
                        if flag == 1:
                            cs.send("Your session has been closed\n".encode())
                            flag = 0
                        elif flag == 2:
                            client.send("Your session has been closed\n".encode())
                            flag = 0
                        socket_list.remove(sock)
                        sock.close()
                        s.send(("END" + "<" + name + ">" + h.END_GET_MSG).encode())
                    # If session being closed is notifies by the other client
                    elif "Your session has been closed" in data:
                        flag = 0
                        socket_list.remove(sock)
                        sock.close()
                        sys.stdout.write(data)
                        sys.stdout.flush()
                    else:
                        sys.stdout.write(data)
                        sys.stdout.flush()


def get_host_port(data):

    """
    function to separate out the host,port number and data from the server message
    :rtype: string, string, string
    :return:  message, host number, port number
	"""
    data = data[2:-1]
    array = data.split(',')
    host = array[0].strip().strip('(').strip("'")
    port = array[1].strip().strip(')')
    return data, host, port


def server_client_connect():
    """
    Function to create two sockets for listening and receiving messages

    :rtype: tuple,socket,socket
    :return:  address, listening socket, receiving socket
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    cl = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    cl.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.settimeout(2)
    cl.settimeout(2)
    r = random.randint(49152, 65535)
    add = tuple(['localhost'] + [r])
    cl.bind(add)
    cl.listen(5)
    return add, cl, s


def print_help():
    """
    Function to print the options available to the client

    """
    print('\nEnter "ONLINE" to check the members online')
    print('Enter "CONNECT <username>", with username of a client to connect to')
    print('Enter "END" to stop communicating with any client')
    print('Enter "LOGOFF" to disconnect from chat service')
    print('Enter "HELP" anytime to read instructions again\n')


def connect(flag, host, name, name2, port, s, socket_list):
    """
    Function to connect the two clients of an active session
    :rtype: socket, int
    :return:  client socket, online flag
    """
    global cs
    try:
        cs = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cs.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        cs.settimeout(2)
        cs.connect((host, int(port)))
        socket_list.append(cs)
        s.send((name + ":" + name2).encode())
        if platform.system() == 'Darwin':
            os.system('clear')
            print_help()
        elif platform.system() == 'Windows':
            os.system('cls')
            print_help()
        print("Connection established with requested client. \n")
        cs.send(("You are now connected to " + name + "\n\n").encode())
        flag = 1
    except IOError:
        print('Client unavailable. Kindly enter another client')
    return cs, flag


def find_between(s, first, last):
    """
    function to find the name of the user between <>
    :rtype: String
    :return:  username of client
    """
    try:
        start = s.index(first) + len(first)
        end = s.index(last, start)
        return s[start:end]
    except ValueError:
        return ""


def main():
    sys.exit(chat_client())


if __name__ == "__main__":
    """
    function to start the client   
    """
    main()
