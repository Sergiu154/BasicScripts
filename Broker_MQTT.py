import socket
from threading import Thread
from scapy.all import *
from scapy.contrib.mqtt import *
import logging
from time import strftime, localtime
import json

logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.DEBUG)

clients_dict = {}


class ClientData:
    def __init__(self, ip=' ', prt='', user='', pswd='', client_id='', is_connected=False):
        self.ip = ip
        self.port = prt
        self.password = pswd
        self.username = user
        self.client_id = client_id
        self.subscribed_topics = []
        self.message_on_topic = {}
        self.has_connected = is_connected
        # tuple (timestamp,binary_file)
        self.event_log = []

    def set_password(self, passwd):
        self.password = passwd

    def set_ip(self, IP):
        self.ip = IP

    def set_username(self, user):
        self.username = user

    def set_port(self, prt):
        self.port = prt

    def add_topic(self, tpc, qos):
        if (tpc, qos) not in self.subscribed_topics:
            self.subscribed_topics.append((tpc, qos))

    def add_event(self, curr_time, cmm):
        self.event_log.append((curr_time, cmm))

    # TO-DO: edge case: client publishes on a topic on which he is not subscribed
    def add_message_on_topic(self, tpc, msg):
        if not self.message_on_topic.get(tpc):
            self.message_on_topic[tpc] = []
        self.message_on_topic[tpc].append(msg)

    def print_client(self):
        print(self.username, self.password, self.ip, self.port, self.client_id)
        for topic in self.subscribed_topics:
            print(topic)
        for key in self.message_on_topic.keys():
            print(self.message_on_topic.get(key))


# get a string o bits from an integer (little-endian)

def get_bits(header):
    bits_string = ''
    for pow in range(0, 8):
        bits_string += str(((header & (2 ** pow)) // (2 ** pow)))
    return bits_string


# skip the variable header, ignoring the variable message length

def pass_message_len(command):
    i = 1

    # while there still is a continuation bit present, skip the byte
    while command[i] >= 128:
        i += 1
    return i


# convert a pack of n bytes passed as a list with the LSB first and returns a decimal value

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


len_and_ints = 'LEN_AND_INT'
len_and_string = 'LEN_AND_STRING'
msgID_and_msg = 'ID_AND_MESSAGE'


# interprets a (field_len,field_value) pattern present in a CONNECT packet
# depending on the type of field_value

def get_field_len_and_value(command, index, combo_type):
    length = decimal_from_n_bytes([command[index + 1], command[index]])

    index += 2
    field_value = ''

    if combo_type == 'ID_AND_MESSAGE':
        while True:
            try:
                field_value += chr(command[index])
                index += 1
            except IndexError as e:
                break
        return index, length, field_value
    else:
        for i in range(0, length):
            field_value += chr(command[index + i])
        index += length
        if combo_type == 'LEN_AND_INT':
            return index, length, int(field_value)
        elif combo_type == 'LEN_AND_STRING':
            return index, length, field_value


# check if the fields are valid, otherwise consider those a probable malicious stream of bytes

def inspect_connect_packet(check):
    return check['proto_len'] != 4 or check['proto_name'] != 'MQTT' \
           or check['keep_alive'].isdigit() == False or check['client_id_length'].isdigit() == False \
           or check['client_id'].isdigit() == False


def connect_comm(command, header_as_bits, client):
    # send Connack packet
    # logging.debug('Hello ' + command.decode())
    # TODO check if the client is in your database(maybe a list of clients)
    #  if True: sessPresent =1

    sess_present = 0

    client.send(bytes(MQTT() / MQTTConnack(sessPresentFlag=sess_present, retcode=0)))

    ip, port = client.getpeername()

    logging.debug('Client connected: ' + ip + ' ' + str(port))

    # jump over msg len, protocol name and length
    # index = pass_message_len(command) + 8

    index = pass_message_len(command) + 1

    index, proto_len, proto_name = get_field_len_and_value(command, index, len_and_string)

    # pass protocol version
    index += 1

    logging.debug('Protocol: ' + proto_name + ' ' + str(proto_len))

    # init fields

    connect_flag = get_bits(command[index])
    username_flag = int(connect_flag[6])
    password_flag = int(connect_flag[7])
    will_flag = int(connect_flag[2])
    # will_retain = 0
    # will_qos = 0
    # will_topic = ''
    # will_topic_len = 0
    # will_msg_len = 0
    # will_msg = ''
    # username_len = 0
    # password_len = 0
    username = ''
    password = ''

    # get to keep_alive 2 byte field
    index += 1

    keep_alive = decimal_from_n_bytes([command[index + 1], command[index]])

    # pass keep alive packet
    index += 2

    index, client_id_length, client_id = get_field_len_and_value(command, index, len_and_ints)

    logging.debug('Client ID: ' + str(client_id))

    # go to the payload whose structure depends on the will_flag

    if will_flag == 1:

        will_retain = int(connect_flag[5])
        will_qos = decimal_from_n_bytes([connect_flag[4], connect_flag[3]])

        if username_flag and password_flag:
            index, will_topic_len, will_topic = get_field_len_and_value(command, index, len_and_string)
            index, will_msg_len, will_msg = get_field_len_and_value(command, index, len_and_string)
            index, username_len, username = get_field_len_and_value(command, index, len_and_string)
            index, password_len, password = get_field_len_and_value(command, index, len_and_string)

    else:

        if username_flag and password_flag:
            index, username_len, username = get_field_len_and_value(command, index, len_and_string)
            index, password_len, password = get_field_len_and_value(command, index, len_and_string)
            logging.debug('Username: ' + username)
            logging.debug('Password: ' + password)

    # TODO use a data structure to store a new incoming client
    #  and handle the CleanSession scenario

    check_dict = {
        'proto_len': proto_len,
        'proto_name': proto_name,
        'keep_alive': str(keep_alive),
        'client_id_length': str(client_id_length),
        'client_id': str(client_id)}

    client_data = ClientData(ip=ip, prt=port, user=username, pswd=password, client_id=str(client_id), is_connected=True)

    if inspect_connect_packet(check_dict) or header_as_bits[:4] != '0000':
        client_data.add_event(strftime("%Y-%m-%d %H:%M:%S", localtime()), str(command))

    return client_data


def publish_comm(command, client, header_as_bits, client_data):
    qos = int(header_as_bits[1]) + 2 * int(header_as_bits[2])
    logging.debug('QOS ' + str(qos))

    index = pass_message_len(command) + 1

    # get topic and message
    index, topic_len, topic = get_field_len_and_value(command, index, len_and_string)
    index, msg_id, message = get_field_len_and_value(command, index, msgID_and_msg)

    # store the data that has been received
    client_data.add_topic(topic, qos)
    client_data.add_message_on_topic(topic, message)

    if not str(topic_len).isdigit() or not str(msg_id).isdigit():
        client_data.add_event(strftime("%Y-%m-%d %H:%M:%S", localtime()), str(command))

        # send the right response packet depending on the QoS level
    if qos == 1:
        client.send(bytes(MQTT() / MQTTPuback(msgid=msg_id)))
    elif qos == 2:
        client.send(bytes(MQTT() / MQTTPubrec(msgid=msg_id)))
        client.send(bytes(MQTT() / MQTTPubcomp(msgid=msg_id)))


def subscribe_comm(command, client, header_as_bits, client_data):
    index = pass_message_len(command) + 1

    msg_id = decimal_from_n_bytes([command[index + 1], command[index]])

    if not str(msg_id).isdigit() or header_as_bits[:4] != '0100':
        client_data.add_event(strftime("%Y-%m-%d %H:%M:%S", localtime()), str(command))

    index += 2
    while True:
        try:
            index, topic_len, topic = get_field_len_and_value(command, index, len_and_string)
            granted_qos = decimal_from_n_bytes([command[index]])
            client_data.add_topic(topic, granted_qos)

            if granted_qos > 2 or (not str(topic_len).isdigit()):
                client_data.add_event(strftime("%Y-%m-%d %H:%M:%S", localtime()), str(command))

            logging.debug('Granted QoS: ' + str(granted_qos))
            index += 1
        except IndexError:
            break

    client.send(bytes(MQTT() / MQTTSuback(msgid=msg_id, retcode=granted_qos)))


def disconnect_command(command, client, header, client_packet):
    with open('data.txt', 'w') as fwrite:
        json.dump(client_packet.__dict__, fwrite, indent=4)


def handle_unexpected_packet(command, client, client_data):
    logging.debug(command.decode('utf-8'))
    client_data.add_event(strftime("%Y-%m-%d %H:%M:%S", localtime()), str(command))


def handle_unexpected_order(command, client, client_data):
    pass


def client_thread(client, command_type, client_data):
    while True:
        command = client.recv(1024)
        if len(command) > 1:

            header_as_bits = get_bits(command[0])
            type_of_command = command_type.get(header_as_bits[4:])

            if type_of_command == 'CONNECT':
                # check if reserved field is 0, otherwise close the connection
                if header_as_bits[:4] != '0000':
                    client.close()
                client_data = connect_comm(command, header_as_bits, client)

            elif client_data.has_connected:
                if type_of_command == 'PUBLISH':
                    publish_comm(command, client, header_as_bits, client_data)

                elif type_of_command == 'SUBSCRIBE':
                    subscribe_comm(command, client, header_as_bits, client_data)

                elif type_of_command == 'DISCONNECT':
                    disconnect_command(command, client, header_as_bits, client_data)
                    break
                elif type_of_command == 'PUBREL':
                    pass
                else:
                    handle_unexpected_packet(command, client, client_data)
                    break

            else:
                handle_unexpected_order(command, client, client_data)

    client.close()


def main():
    command_type = {'1000': 'CONNECT',
                    '0001': 'SUBSCRIBE',
                    '1100': 'PUBLISH',
                    '0111': 'DISCONNECT',
                    '0110': 'PUBREL'}

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('', 1883))
        server.listen()
        while True:
            client, addr = server.accept()
            client_data = ClientData()
            Thread(target=client_thread, args=(client, command_type, client_data)).start()


if __name__ == '__main__':
    main()
