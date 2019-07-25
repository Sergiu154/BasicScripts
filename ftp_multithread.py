import socket
from threading import Thread


def clientThread(connection):
    is_active = True  # TO-DO implement the functionality to re-login
    while is_active:  # meanwhile the user is permanently connected to the server until he quits
        login(connection)


def login(clientsocket):
    clientsocket.send(b'220 Welcome to ProXad FTP server\n')
    print(1)
    username = clientsocket.recv(4096).decode('utf-8')
    clientsocket.send(b'331 Please specify the password\n')
    password = clientsocket.recv(4096).decode('utf-8')
    print(username, end='')
    print(password)
    clientsocket.send(b'430 Invalid username or password\n')


def main():
    port = 21
    socketserver = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socketserver.bind(('', port))
    socketserver.listen(1000)
    while True:
        clientsocket, address = socketserver.accept()
        ip, prt = address
        print('Client address is ' + str(ip) + ' ' + str(prt))
        try:
            Thread(target=clientThread, args=(clientsocket,)).start()
        except:
            print('Thread did not start.')
    socketserver.close()


if __name__ == '__main__':
    main()
