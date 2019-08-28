import struct


# will packet which is part of connect

class Will:

    def __init__(self, msg='', topic='', topic_len='0', msg_len='0', qos=0, flag=0):
        self.msg = msg
        self.topic = topic
        self.topic_len = topic_len
        self.msg_len = msg_len
        self.qos = qos
        self.flag = flag


# 4-bits representation of a mqtt packet code
command_type = {'1000': 'CONNECT',
                '0001': 'SUBSCRIBE',
                '1100': 'PUBLISH',
                '0111': 'DISCONNECT',
                '0110': 'PUBREL',
                '0011': 'PINGREQ'}


# get a 8-bits string from an integer (little-endian)

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


packet_pair = {'len+int': 0,
               'len+string': 1,
               'id+message': 2}


# there are 3 type of subpackets to extract
# 1. length + integer -> 'len+int'
# 2.length + string -> 'len+string'
# 3. messageId + message -> 'id+message'

# index keeps the count of the bytes in the packet
# it is used and incremented to reach specific packet fields
# and to extract their values

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
        return index, str(length[0]), field_value
    else:
        # otherwise, the length of the message is known and the message is processed easier
        field_value = ''.join(chr(x) for x in current_packet[index:index + length[0]])
        index += length[0]
        return index, str(length[0]), field_value
