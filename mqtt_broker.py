import socket
import pyshark
import logging
import json

logging.basicConfig(level=logging.DEBUG)


class ClientData:
    def __init__(self, ip=' ', prt='', user='', pswd=''):
        self.password = pswd
        self.username = user
        self.ip = ip
        self.port = prt
        self.subscribed_topics = []
        self.message_on_topic = {}

    def set_password(self, passwd):
        self.password = passwd

    def set_ip(self, IP):
        self.ip = IP

    def set_username(self, user):
        self.username = user

    def set_port(self, prt):
        self.port = prt

    def add_topic(self, tpc):
        if tpc not in self.subscribed_topics:
            self.subscribed_topics = []
        self.subscribed_topics.append(tpc)

    # TO-DO: edge case: client publishes on a topic on which he is not subscribed
    def add_message_on_topic(self, tpc, msg):
        if not self.message_on_topic.get(tpc):
            self.message_on_topic[tpc] = []
        self.message_on_topic[tpc].append(msg)

    def print_client(self):
        print(self.username, self.password, self.ip, self.port)
        for topic in self.subscribed_topics:
            print(topic)
        for key in self.message_on_topic.keys():
            print(self.message_on_topic.get(key))


def get_bits(header):
    bits_string = ''
    for pow in range(0, 8):
        bits_string += str(((header & (2 ** pow)) // (2 ** pow)))
    return bits_string


def get_address(packet, clients_dict):
    client_port = packet['tcp'].get_field_by_showname('Source Port')
    if clients_dict.get((packet.ip.src, client_port)):
        pass
    else:
        clients_dict[(packet.ip.src, client_port)] = ClientData(packet.ip.src, client_port)
    return tuple((packet.ip.src, client_port))


# convert a hex into a 8-bits string
def parse_header(header):
    hex_dict = {'0': 0,
                '1': 1,
                '2': 2,
                '3': 3,
                '4': 4,
                '5': 5,
                '6': 6,
                '7': 7,
                '8': 8,
                '9': 9,
                'a': 10,
                'b': 11,
                'c': 12,
                'd': 13,
                'e': 14,
                'f': 15}

    for index in range(0, len(header)):
        if header[index] not in ['0', 'x']:
            break
    parsed_header = header[index:]
    p = 1
    header_flag = 0
    for x in parsed_header[::-1]:
        header_flag += p * hex_dict[x]
        p *= 16
    return get_bits(header_flag)


def connect(packet, clients_dict, addr):
    username = ''
    password = ''
    client_id = ''
    ip, port = addr
    logging.debug('Connection From: ' + ip + ' ' + port)

    connect_flag = packet['mqtt'].get_field_by_showname('Connect Flags')
    flag_bits = parse_header(connect_flag)[::-1]
    if flag_bits[0]:
        username += packet['mqtt'].get_field_by_showname('User Name')
        if flag_bits[1]:
            password += packet['mqtt'].get_field_by_showname('Password')

    client_id += packet['mqtt'].get_field_by_showname('Client ID')
    clients_dict[addr].set_username(username)
    clients_dict[addr].set_password(password)

    logging.debug(username + ' ' + password + ' ' + client_id)


def subscribe(packet, clients_dict, addr):
    topic = ''
    topic += packet['mqtt'].get_field_by_showname('Topic')
    clients_dict[addr].add_topic(topic)
    logging.debug(topic)


def publish(packet, clients_dict, addr):
    topic = ''
    message = ''
    topic += packet['mqtt'].get_field_by_showname('Topic')
    message += packet['mqtt'].get_field_by_showname('Message')
    clients_dict[addr].add_message_on_topic(topic, message)
    print(clients_dict[addr].message_on_topic)
    logging.debug(topic + '  ' + message)


def disconenct(packet, clients_dict, addr):
    clients_dict[addr].print_client()
    with open('data.txt', 'a') as fwrite:
        json.dump(clients_dict[addr].__dict__, fwrite, indent=4)


def handle_commands(bit_string, command_type, packet, clients_dict):
    default_msg = 'Don\'t have that one yet'
    commd = command_type.get(bit_string[4:], default_msg)

    addr = get_address(packet, clients_dict)

    if commd == 'CONNECT':
        connect(packet, clients_dict, addr)

    elif commd == 'SUBSCRIBE':
        subscribe(packet, clients_dict, addr)

    elif commd == 'PUBLISH':
        publish(packet, clients_dict, addr)

    elif commd == 'DISCONNECT':
        disconenct(packet, clients_dict, addr)


def clientThread(capture, command_type, clients_dict):
    for packet in capture:
        # get_address(packet, clients_dict)
        header = str(packet['mqtt'].get_field_by_showname('Header Flags'))
        bit_string = parse_header(header)
        # print(bit_string[4:])
        handle_commands(bit_string, command_type, packet, clients_dict)


def main():
    clients_dict = {}
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(('', 1883))
        server.listen()
        field_list = ['Topic', 'User Name', 'Password', 'Message']
        command_type = {'1000': 'CONNECT',
                        '0001': 'SUBSCRIBE',
                        '1100': 'PUBLISH',
                        '0111': 'DISCONNECT'}

        while True:
            conn, addr = server.accept()
            # star capturing the packets
            capture = pyshark.LiveCapture(interface='lo', display_filter='mqtt')
            capture.sniff(timeout=2)
            clientThread(capture, command_type, clients_dict)


if __name__ == '__main__':
    main()
