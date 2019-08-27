from MQTT_utils.mqtt_parse import *


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
