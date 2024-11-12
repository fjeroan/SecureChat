# Pradeepa Shri Jothinathan - 1001241839

import socket
import time
import select
import headers as h

# empty HOST String
HOST = ''
# list of sockets
SOCKET_LIST = []
# buffer size
RECV_BUFF = 4096
# port number
PORT = 6000
# dict of active users
activeUsers = {}
# dict of active sessions
activeSessions = {}
# dict to detect the active sessions
new = {}


def find_between(s, first, last):
    """
    Function to find the username from the given string
    :param s: String
    :param first: First symbol
    :param last: Last symbol
    :return: returns the username
    """
    try:
        start = s.index(first) + len(first)
        end = s.index(last, start)
        return s[start:end]
    except ValueError:
        return ""


def start_server():
    """
    Function to initialize the server with the given address and port
    :return: server
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(10)
    SOCKET_LIST.append(s)
    print("Server has been initialized! \n")
    print("Welcome to Instant Messaging System!!! \n")
    return s


def accept_connection(s):
    """
    Function for connecting, logging off and disconnecting the user from the server and other users
    :param s: server
    """
    quit_flag = False
    activeSessions = {}
    # while loop to repeatedly check for the data being sent
    while not quit_flag:
        # using Non-Blocking sockets for multi-threading
        ready_to_read, ready_to_write, in_error = select.select(SOCKET_LIST, [], [], 0)
        # each socket in the waiting list
        for sock in ready_to_read:

            # if new connection is requested
            if sock == s:
                # accept connection
                sockfd, addr = s.accept()
                # send acknowledgement
                sockfd.send("connection".encode())
                time.sleep(1)
                while True:
                    # getting the username from the connection
                    alias = sockfd.recv(RECV_BUFF)
                    alias = alias.decode()
                    # checking if it is in the dict of active users
                    if alias in activeUsers:
                        sockfd.send("False".encode())
                    else:
                        sockfd.send("True".encode())
                        SOCKET_LIST.append(sockfd)
                        address = sockfd.recv(RECV_BUFF)
                        address = address.decode()
                        print("Listening port assigned is " + address)
                        # storing the username and the address
                        activeUsers[alias] = address
                        break

            # when its just data, not a new connection
            else:
                try:
                    # get the data from the connection
                    data = sock.recv(RECV_BUFF)
                    data = data.decode()
                    # if the data is not empty
                    if data:
                        # If client wants to connect to another user
                        if "CONNECT" in data:
                            try:
                                print("\n" + data)
                                # find the username from the data
                                data = find_between(data, "<", ">")
                                if data == '':
                                    sock.send("Please enter the username in your request.\n".encode())
                                else:
                                    # checking if the user is already in an active session
                                    if data in activeUsers:
                                        if data in activeSessions:
                                            sock.send("Requested user is already chatting with someone else.\n".encode())
                                        else:
                                            # creating a connection with the other user
                                            str1 = str(activeUsers[data])
                                            str1 = "CONNECT <" + str1 + ">"
                                            sock.send(str1.encode())
                                            m = sock.recv(RECV_BUFF)
                                            m = m.decode()
                                            k = m.split(':')
                                            activeSessions[k[0]] = k[1]
                                            activeSessions[k[1]] = k[0]
                                    else:
                                        sock.send("Requested user is not available\n".encode())
                            except:
                                print("Error while connecting")

                        # If client raises disconnect request
                        elif "LOGOFF" in data:
                            try:
                                # removing the client from the list of known sockets
                                method = data.split()
                                msg1 = " ".join(method[2:5])
                                msg2 = " ".join(method[5:])
                                print("\n" + msg1 + "\n" + msg2)
                                user = find_between(data, "<", ">")
                                # deleting from active users dict
                                del activeUsers[user]
                                SOCKET_LIST.remove(sock)
                                sock.send(h.LOGOFF_PUT_MSG.encode())
                            except:
                                print("Error while disconnecting from server")

                        # If client wants to see the users who are online
                        elif "ONLINE" in data:
                            try:
                                
                                print("\n" + data)
                                aS = set()
                                for y in activeSessions.keys():
                                    aS.add(y)
                                    aS.add(activeSessions[y])
                                aU = set(activeUsers.keys())
                                on = aU - aS
                                online = ', '.join(on)
                                if online != '':
                                    res = "ONLINE: " + online
                                else:
                                    res = ''
                                sock.send((h.ONLINE_PUT_MSG + res).encode())
                            except:
                                print("Cannot retrieve Online users")

                        # If client notifies end of session with user
                        elif "END" in data:
                            try:
                                method = data.split()
                                msg1 = " ".join(method[1:4])
                                msg2 = " ".join(method[4:])
                                print("\n" + msg1 + "\n" + msg2)
                                data = find_between(data, "<", ">")
                                # find the two clients to be removed from active sessions
                                for key, value in activeSessions.items():
                                    if data != key:
                                        new[key] = value
                                        activeSessions = new
                                        sock.send(h.END_PUT_MSG.encode())
                                    elif key == data:
                                        #deleting both the clients from active sessions, so that they are available to chat
                                        del activeSessions[data]
                                        del activeSessions[value]
                            except:
                                print()

                        else:
                            sock.send("Unknown Request".encode())
                    else:
                        if sock in SOCKET_LIST:
                            SOCKET_LIST.remove(sock)
                except IOError as e:
                    print(e)
                    continue
    s.close()


def main(): 
    """
    function to start the server
    """
    s = start_server()
    accept_connection(s)


if __name__ == "__main__":
    main()
