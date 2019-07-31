from threading import Thread
import socket


def greeting_n_login(clientsocket, aString, addr):
    print('User connected', addr, sep='\n')
    clientsocket.send(aString)
    response = [x for x in str(clientsocket.recv(4096)).split('\\')]
    print('Username: ', response[35][3:])
    username = response[35][3:]

    err_start = b"\x32\x00\x00\x02\xff\xa2\x06\x23\x32\x38\x30\x30\x30\x41\x63\x63\x65\x73\x73\x20\x64\x65\x6e\x69" \
                b"\x65\x64\x20\x66\x6f\x72\x20\x75\x73\x65\x72\x20\x27"

    err_end = b"\x27\x40\x27\x6c\x6f\x63\x61\x6c\x68\x6f\x73\x74\x27"

    err_middle = bytes(username, 'utf-8')

    return err_start + err_middle + err_end


def clientThread(clientsocket, addr):
    err_response = greeting_n_login(clientsocket,
                                    b"\x5b\x00\x00\x00\x0a\x35\x2e\x37\x2e\x32\x37\x2d\x30\x75\x62\x75\x6e\x74\x75\x30\x2e"
                                    b"\x31\x38\x2e\x30\x34\x2e\x31\x00\x03\x00\x00\x00\x03\x64\x25\x35\x48\x21\x59\x7d\x00"
                                    b"\xff\xf7\x08\x02\x00\xff\x81\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x16\x14\x2f"
                                    b"\x64\x49\x4a\x51\x41\x2e\x66\x65\x7f\x00\x6d\x79\x73\x71\x6c\x5f\x6e\x61\x74\x69\x76"
                                    b"\x65\x5f\x70\x61\x73\x73\x77\x6f\x72\x64\x00", addr)

    clientsocket.send(err_response)

    clientsocket.close()



port = 3306


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as socketserver:
        socketserver.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        socketserver.bind(('', port))
        socketserver.listen(5)
        while True:
            clientsocket, addr = socketserver.accept()
            try:
                Thread(target=clientThread, args=(clientsocket, addr)).start()
            except:
                print('Thread did not start')


if __name__ == '__main__':
    main()
