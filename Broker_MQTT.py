import socket
from threading import Thread
from scapy.all import *
from scapy.contrib.mqtt import *
import logging
import struct

logging.basicConfig(level=logging.DEBUG)


# get a string o bits from an integer (little-endian)

def get_bits(header):
    bits_string = ''
    for pow in range(0, 8):
        bits_string += str(((header & (2 ** pow)) // (2 ** pow)))
    return bits_string


def pass_message_len(command):
    i = 1
    while command[i] == 128:
        i += 1
    return i


def decimal_from_n_bytes(integers_list):
    bytes_list = []
    for integer in integers_list:
        bytes_list.append(get_bits(integer))
    one_string = ''
    for byte in bytes_list:
        one_string += byte
    pow = 1
    decimal = 0
    for bit in one_string:
        if bit == '1':
            decimal += pow
        pow *= 2
    return decimal


# TO-DO - function to parse the packet for a len num of 2 bytes and an int or a string

len_and_ints = 'LEN_AND_INT'
len_and_string = 'LEN_AND_STRING'


def get_field_len_and_value(command, index, combo_type):
    length = decimal_from_n_bytes([command[index + 1], command[index]])

    index += 2
    print(length)
    field_value = ''
    for i in range(0, length):
        field_value += chr(command[index + i])
        # print(chr(command[index + i]))

    index += length

    if combo_type == 'LEN_AND_INT':
        return index, length, int(field_value)
    elif combo_type == 'LEN_AND_STRING':
        return index, length, field_value


def connect_comm(command, client):
    client.send(bytes(MQTT() / MQTTConnack()))

    # jump over msg len, protocol name and length
    index = pass_message_len(command) + 8

    connect_flag = get_bits(command[index])
    username_flag = connect_flag[0]
    password_flag = connect_flag[1]
    will_flag = connect_flag[6]

    # get to keep_alive 2 byte field
    index += 1

    keep_alive = decimal_from_n_bytes([command[index + 1], command[index]])

    index += 2

    index, client_id_length, client_id = get_field_len_and_value(command, index, len_and_ints)

    print('Client id is :', int(client_id))

    # go to the payload whose structure depends on the will_flag

    if will_flag == 1:
        will_retain = connect_flag[3]

        if username_flag and password_flag:
            index, will_topic_len, will_topic = get_field_len_and_value(command, index, len_and_string)
            index, will_msg_len, will_msg = get_field_len_and_value(command, index, len_and_string)
            index, username_len, username = get_field_len_and_value(command, index, len_and_string)
            index, password_len, password = get_field_len_and_value(command, index, len_and_string)

    else:

        if username_flag and password_flag:
            index, username_len, username = get_field_len_and_value(command, index, len_and_string)
            index, password_len, password = get_field_len_and_value(command, index, len_and_string)
            print('Username len and user:', str(username_len) + ' ' + username)
            print('Password len and password:', str(password_len) + ' ' + password)


def publish_comm(command, client, header_as_bits):
    qos = int(header_as_bits[1]) + 2 * int(header_as_bits[2])
    print('QOS', qos)

    index = pass_message_len(command) + 1

    index, topic_len, topic = get_field_len_and_value(command, index, len_and_string)
    index, msg_id, message = get_field_len_and_value(command, index, len_and_string)

    if qos == 1:
        client.send(bytes(MQTT() / MQTTPuback(msgid=msg_id)))


def subscribe_comm(command, client, header):
    client.send(bytes(MQTT() / MQTTSuback()))


def disconnect_command(command, client, header):
    pass


def client_thread(client, command_type):
    while True:
        command = client.recv(1024)
        if len(command) > 1:
            print(command[0])

            header_as_bits = get_bits(command[0])
            type_of_command = command_type.get(header_as_bits[4:])

            if type_of_command == 'CONNECT':
                connect_comm(command, client)

            elif type_of_command == 'PUBLISH':
                publish_comm(command, client, header_as_bits)

            elif type_of_command == 'SUBSCRIBE':

                subscribe_comm(command, client, header_as_bits)

            elif type_of_command == 'DISCONNECT':

                disconnect_command(command, client, header_as_bits)

                break
    client.close()


def main():
    command_type = {'1000': 'CONNECT',
                    '0001': 'SUBSCRIBE',
                    '1100': 'PUBLISH',
                    '0111': 'DISCONNECT'}

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('', 1883))
        server.listen()
        while True:
            client, addr = server.accept()
            Thread(target=client_thread, args=(client, command_type)).start()


if __name__ == '__main__':
    main()
