import base64
import socket
import logging
from threading import Thread

logging.basicConfig(format="%(asctime)s  - %(message)s", level=logging.DEBUG)


def decode_message_login(clientsocket):
    clientsocket.send(b'334 VXNlcm5hbWU6\n')
    username = base64.b64decode(clientsocket.recv(1024)).decode('utf-8')
    clientsocket.send(b'334 UGFzc3dvcmQ6\n')
    password = base64.b64decode(clientsocket.recv(1024)).decode('utf-8')
    return username, password


def login(clientsocket, ip, port):
    logging.debug('User connected')
    logging.debug(str(ip) + ' ' + str(port))
    clientsocket.send(b'220 smtp.server.com Simple Mail Transfer Service Ready\n')
    init_response = clientsocket.recv(1024).decode('utf-8')
    if init_response[:4] == 'EHLO':
        if len(init_response) == 5:
            init_response = 'None'
        logging.debug(init_response)
        clientsocket.send(b'250-smtp.server.com Hello client.example.com\n')
        clientsocket.send(b'250-SIZE 1000000\n')
        clientsocket.send(b'250 AUTH LOGIN PLAIN CRAM-MD5\n')
        type_auth = clientsocket.recv(1024).decode('utf-8').strip('\n').split(' ')
        possible_commd = ['LOGIN', 'PLAIN', 'CRAM-MD5']
        if type_auth[0] == 'AUTH' and type_auth[1] in possible_commd and len(type_auth) == 2:
            if type_auth[1] == 'PLAIN':
                clientsocket.send(b'334\n')
                login_response = base64.b64decode(clientsocket.recv(1024)).decode('utf-8')
                logging.debug('USER + PASS: ' + login_response)

            elif type_auth[1] == 'LOGIN':
                username, pswd = decode_message_login(clientsocket)
                logging.debug('USER: ' + username + ' ' + 'PASS: ' + pswd)
                clientsocket.send(b'235 2.7.0 Authentication successful\n')
                logging.debug('Command after login: ' + clientsocket.recv(1024).decode('utf-8'))
                clientsocket.close()
            else:
                attempt = clientsocket.recv(1024).decode('utf-8')
                logging.debug('Attempt ' + attempt)
    else:
        logging.debug("UNKNOWN: " + init_response)
        clientsocket.close()


def main():
    port = 587
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as socketserver:
        socketserver.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        socketserver.bind(('', port))
        socketserver.listen(10)
        while True:
            clientsocket, addr = socketserver.accept()
            ip, port = addr
            Thread(target=login, args=(clientsocket, ip, port)).start()


if __name__ == '__main__':
    main()
