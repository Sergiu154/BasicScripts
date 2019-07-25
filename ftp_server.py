import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

host = socket.gethostname()

port = 21

s.bind(('', port))


s.listen(5)

while True:
    clientsocket, addr = s.accept()
    print(host, addr)
    clientsocket.send('220 Welcome to ProXad FTP server'.encode('ascii'))
    username = clientsocket.recv(1024)
    print('a')
    clientsocket.send('331 Please specify the password.'.encode('ascii'))
    password = clientsocket.recv(1024)
    clientsocket.close()