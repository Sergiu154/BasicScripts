import socket
import pyshark
import logging
from threading import Thread

logging.basicConfig(level=logging.DEBUG)


def get_bits(header):
    bits_string = ''
    for pow in range(0, 8):
        bits_string += str(((header & (2 ** pow)) // (2 ** pow)))
    return bits_string


def get_address(packet):
    if packet['tcp'].get_field_by_showname('Sequence number') == '1':
        logging.debug('Connection From: ' + ' ' + packet.ip.src + ' ' +
                      packet['tcp'].get_field_by_showname('Source Port'))


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


def handle_commands(bit_string, command_type, packet):
    default_msg = 'Don\'t have that one yet'
    commd = command_type.get(bit_string[4:], default_msg)

    if commd == 'CONNECT':
        connect_flag = packet.get_field_by_showname('Connect Flags')
        flag_bits = parse_header(connect_flag)[::-1]
        username = ''
        password = ''
        if flag_bits[0]:
            username += packet.get_field_by_showname('User Name')
            if flag_bits[1]:
                password += packet.get_field_by_showname('Password')
        logging.debug(username + ' ' + password)

    elif commd == 'SUBSCRIBE':
        topic = packet.get_field_by_showname('Topic')
        logging.debug(topic)

    elif commd == 'PUBLISH':
        topic = packet.get_field_by_showname('Topic')
        message = packet.get_field_by_showname('Message')
        logging.debug(topic + '\n' + message)


def clientThread(capture, command_type):
    for packet in capture:
        get_address(packet)
        header = str(packet['mqtt'].get_field_by_showname('Header Flags'))
        bit_string = parse_header(header)
        # print(bit_string[4:])
        handle_commands(bit_string, command_type, packet['mqtt'])


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(('127.0.0.1', 1883))
        server.listen()
        field_list = ['Topic', 'User Name', 'Password', 'Message']
        command_type = {'1000': 'CONNECT',
                        '0001': 'SUBSCRIBE',
                        '1100': 'PUBLISH'}

        while True:
            conn, addr = server.accept()
            # star capturing the packets
            capture = pyshark.LiveCapture(interface='lo', display_filter='mqtt')
            capture.sniff(timeout=2)
            clientThread(capture, command_type)


if __name__ == '__main__':
    main()
