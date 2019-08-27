from MQTT_utils.mqtt_parse import *


def parse_subscribe_packet(current_packet, header, ip, port):
    index = pass_message_len(current_packet) + 1
    msg_id = struct.unpack('>H', current_packet[index:index + 2])

    if not str(msg_id[0]).isdigit() or header[:4] != '0100':
        return None
    index += 2

    while True:
        try:
            index, topic_len, topic = get_packet_field(current_packet, index, 'len+string')
            granted_qos = current_packet[index]
            index += 1

            if granted_qos > 2 or (not topic_len.isdigit()):
                return None

        except struct.error:
            break
    param_dict = {
        'ip': ip,
        'port': port,
        'command_name': 'Subscribe',
        'topic': topic,
        'msg_id': msg_id[0],
        'qos': granted_qos

    }

    return param_dict
