import socket
from threading import Thread


def parse_command(m_text):
    index = m_text.find(' ')
    comm = m_text[0:index]
    arg = m_text[index + 1:]
    return comm, arg


def request_comm(clientsocket, one_string):
    clientsocket.send(one_string)
    arg = clientsocket.recv(4096).decode('utf-8')
    return parse_command(arg)


def clientThread(clientsocket, ip, prt):
    comm_user, user = request_comm(clientsocket, b'220 Welcome to ProXad FTP server\n')

    if comm_user.upper() != 'USER':
        print(str(ip) + ' ' + str(prt) + ' ' + 'UNKNOWN' + ' ' + comm_user + ' ' + user.strip('\n') + '\n')
        clientsocket.close()
    else:
        comm_pass, paswd = request_comm(clientsocket, b'331 Please specify the password\n')

        message = 'LOGIN'

        if comm_pass.upper() != 'PASS':
            message = "UNKNOWN"
            print(str(ip) + ' ' + str(prt) + ' ' + message + ' ' + comm_pass + ' ' + paswd.strip('\n') + '\n')

        else:
            print(str(ip) + ' ' + str(prt) + ' ' + message + ' ' + user.strip('\n') + ' ' + paswd.strip('\n') + '\n')
        clientsocket.send(b'430 Invalid username or password\n')
        clientsocket.close()


def main():
    port = 21
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as socketserver:
        socketserver.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        socketserver.bind(('', port))
        socketserver.listen(1000)
        while True:
            clientsocket, address = socketserver.accept()
            ip, prt = address
            try:
                Thread(target=clientThread, args=(clientsocket, ip, prt)).start()
            except:
                print('Thread did not start.')


if __name__ == '__main__':
    main()
