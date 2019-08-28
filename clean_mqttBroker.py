from scapy.all import *
from scapy.contrib.mqtt import *
from time import strftime, localtime
from MQTT_utils.mqtt_connect import *
from MQTT_utils.mqtt_publish import *
from MQTT_utils.mqtt_subscribe import *

logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.DEBUG)


def connect(current_packet, header, client, addr):
    # send connack packet
    client.send(bytes(MQTT() / MQTTConnack(sessPresentFlag=0, retcode=0)))

    ip, port = addr
    logging.debug('Client connected: ' + ip + ' ' + str(port))

    to_check, connection_data, connect_flag = parse_connect_packet(current_packet, ip, port)

    logging.debug('Protocol: ' + str(to_check['proto_name']) + ' ' + str(to_check['proto_len']))
    logging.debug('Username: ' + connection_data['username'])
    logging.debug('Password: ' + connection_data['password'])

    # inspect connect packet for malformed data

    if inspect_connect_packet(to_check) or header[:4] != '0000' or connect_flag[0] != '0':
        print(strftime("%Y-%m-%d %H:%M:%S", localtime()), str(current_packet))
    else:
        server_event_known_command(connection_data)


def publish(current_packet, header, client, addr):
    ip, port = addr

    # parse packet
    connection_data = parse_publish_packet(current_packet, header, ip, port)

    # check a publish packet for some malformed data
    if inspect_publish_packet(connection_data):
        print(strftime("%Y-%m-%d %H:%M:%S", localtime()), str(current_packet))
    else:
        server_event_known_command(connection_data)

    # send the appropriate packet for the received QoS
    msg_id = int(connection_data['msg_id'])
    if connection_data['qos'] == 1:
        client.send(bytes(MQTT() / MQTTPuback(msgid=msg_id)))
    elif connection_data['qos'] == 2:
        client.send(bytes(MQTT() / MQTTPubrec(msgid=msg_id)))
        client.send(bytes(MQTT() / MQTTPubcomp(msgid=msg_id)))


def subscribe(current_packet, header, client, addr):
    ip, port = addr

    connection_data = parse_subscribe_packet(current_packet, header, ip, port)
    # receive the incoming packet, if it is None, the packet is no valid
    if connection_data:
        server_event_known_command(connection_data)
        client.send(
            bytes(MQTT() / MQTTSuback(msgid=int(connection_data['msg_id']), retcode=int(connection_data['qos']))))


# handle an unexpected packet and set it's current state depending on the Connect packet

def server_event_unexpected_packet(command, client, has_connected):
    logging.debug(command.decode('utf-8'))
    state = 'Before Connect'
    if has_connected:
        state = 'After Connect'

    print(strftime("%Y-%m-%d %H:%M:%S", localtime()), str(command), state)


# print the fields and the value of a valid packet

def server_event_known_command(param_dict):
    for key in param_dict.keys():
        print(key, param_dict.get(key))


def client_thread(client, command_type, addr):
    has_connected = False
    while True:
        command = client.recv(1024)
        if len(command) > 1:

            header_as_bits = get_bits(command[0])
            type_of_command = command_type.get(header_as_bits[4:])

            if type_of_command == 'CONNECT':
                # check if reserved field is 0, otherwise close the connection
                if header_as_bits[:4] != '0000':
                    client.close()
                connect(command, header_as_bits, client, addr)
                has_connected = True

            elif has_connected:
                if type_of_command == 'PUBLISH':
                    publish(command, header_as_bits, client, addr)

                elif type_of_command == 'SUBSCRIBE':
                    subscribe(command, header_as_bits, client, addr)

                elif type_of_command == 'DISCONNECT':
                    break
                elif type_of_command == 'PUBREL' or type_of_command == 'PINGREQ':
                    pass
                else:
                    server_event_unexpected_packet(command, client, has_connected)

            else:
                server_event_unexpected_packet(command, client, has_connected)

    client.close()


def main():
    # use a socket, bind it to a specific port and listen the incoming connections
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('', 1883))
        server.listen()
        while True:
            client, addr = server.accept()
            Thread(target=client_thread, args=(client, command_type, addr)).start()


if __name__ == '__main__':
    main()
