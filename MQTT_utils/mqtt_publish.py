from MQTT_utils.mqtt_parse import *


def parse_publish_packet(current_packet, header, ip, port):
    qos = int(header[1]) + 2 * int(header[2])

    index = pass_message_len(current_packet) + 1
    index, topic_len, topic = get_packet_field(current_packet, index, 'len+string')

    msg_id = 0
    if qos > 0:
        index, msg_id, message = get_packet_field(current_packet, index, 'id+message')
    else:
        msg = ''
        while True:
            try:
                msg += chr(current_packet[index])
                index += 1
            except IndexError:
                break
        message = msg[:len(msg) - 2]
    param_dict = {
        'ip': ip,
        'port': port,
        'command_name': 'Publish',
        'topic': topic,
        'topic_len': str(topic_len),
        'msg_id': str(msg_id),
        'message': message,
        'qos': qos
    }

    return param_dict


def inspect_publish_packet(param_dict):
    return (not param_dict['topic_len'].isdigit()) or (param_dict['qos'] > 0 and not param_dict['msg_id'].isdigit())
