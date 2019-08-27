import struct


class Will:

    def __init__(self, msg='', topic='', topic_len='0', msg_len='0', qos=0, flag=0):
        self.msg = msg
        self.topic = topic
        self.topic_len = topic_len
        self.msg_len = msg_len
        self.qos = qos
        self.flag = flag


packet_pair = {'len+int': 0,
               'len+string': 1,
               'id+message': 2}


# will packet which is part of connect


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


# there are 3 type of subpackets to extract
# 1. length + integer -> 'len+int'
# 2.length + string -> 'len+string'
# 3. messageId + message -> 'id+message'

def get_packet_field(current_packet, index, combination):
    length = struct.unpack('>H', current_packet[index:index + 2])
    index += 2
    field_value = ''

    if combination == 'id+message':
        # in case Qos > 0 , there is an additional field 'Message' which length is not specified
        while True:
            try:
                field_value += chr(current_packet[index])
                index += 1
            except IndexError:
                break
        return index, length[0], field_value
    else:
        field_value = ''.join(chr(x) for x in current_packet[index:index + length[0]])
        index += length[0]
        return index, str(length[0]), field_value


def parse_connect_packet(current_packet, ip, port):
    # pass over variable message length field
    index = pass_message_len(current_packet) + 1

    index, proto_len, proto_name = get_packet_field(current_packet, index, 'len+string')

    # pass protocol version
    index += 1
    connect_flag = get_bits(current_packet[index])

    username_flag = int(connect_flag[6])
    password_flag = int(connect_flag[7])
    will = Will()
    will.flag = int(connect_flag[2])
    username = ''
    password = ''

    index += 1
    keep_alive = struct.unpack('>H', current_packet[index:index + 2])
    index += 2
    index, id_length, client_id = get_packet_field(current_packet, index, 'len+string')

    if will.flag == 1:
        will.qos = int(connect_flag[3]) + 2 * int(connect_flag[4])
        if username_flag and password_flag:
            index, will.topic_len, will.topic = get_packet_field(current_packet, index, 'len+string')
            index, will.msg_len, will.msg = get_packet_field(current_packet, index, 'len+string')
            index, username_len, username = get_packet_field(current_packet, index, 'len+string')
            index, password_len, password = get_packet_field(current_packet, index, 'len+string')
    else:
        if username_flag and password_flag:
            index, username_len, username = get_packet_field(current_packet, index, 'len+string')
            index, password_len, password = get_packet_field(current_packet, index, 'len+string')

    check_dict = {
        'proto_len': proto_len,
        'proto_name': proto_name,
        'keep_alive': str(keep_alive[0]),
        'client_id_length': str(id_length),
        'client_id': str(client_id),
        'will': will
    }
    param_dict = {'ip': ip,
                  'port': port,
                  'command_name': 'Connect',
                  'username': username,
                  'password': password,
                  'client_id': client_id,
                  'has_connected': True,
                  'will_message': will.msg,
                  'will_topic': will.topic

                  }
    return check_dict, param_dict, connect_flag


def inspect_connect_packet(check):
    return check['proto_len'] != '4' or check['proto_name'] != 'MQTT' \
           or check['keep_alive'].isdigit() == False \
           or check['client_id_length'].isdigit() == False or check['will'].topic_len.isdigit() == False \
           or check['will'].msg_len.isdigit() == False or check['will'].qos > 2
