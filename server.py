import socket

socketserver = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

port = 12345

host = socket.gethostname()

socketserver.bind(('', port))

socketserver.listen(10)
f = open('info.txt', 'a')
while 1:
    clientsocket, addr = socketserver.accept()
    print("We have a connection from {}".format(addr))

    msg = '220 Welcome to ProXad FTP server\n'

    clientsocket.send(msg.encode('ascii'))
    clientsocket.send(b'USER ')
    username = clientsocket.recv(4096)
    clientsocket.send(b'331 Please specify the password\n')
    clientsocket.send(b'PASS ')
    password = clientsocket.recv(4096)
    if username == '' or password == '':
        clientsocket.close()
        break

    f.write('USER: ' + username.decode('ascii'))
    f.write(password.decode('ascii') + '\n')
    clientsocket.send(b'Invalid username or password')
    clientsocket.close()
    # close the socket
f.close()
