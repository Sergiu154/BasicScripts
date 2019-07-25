import socket

# socket object
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# local machine name

host = socket.gethostname()

port = 8080
# coonect to hostname
s.connect(('', port))

msg = s.recv(1024)  # receive a message no more than 1024 bytes
# username = input()

print(msg.decode('ascii'))

s.close()
