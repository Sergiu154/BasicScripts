import paho.mqtt.client as mqtt
import time


def on_connect(client, userdata, flags, rc):
    print("Connected " + str(flags['session present']))
    print("Connection result: " + str(rc))


def on_disconnect(client, userdata, rc):
    print("User disconnected")


def on_log(client, userdata, level, string):
    print(string)


def on_message(client, userdata, msg):
    print(msg.topic + ' ' + str(msg.payload))


client = mqtt.Client(client_id='12', clean_session=False)

client.on_connect = on_connect
client.on_disconnect = on_disconnect
client.on_message = on_message

client.username_pw_set(username="Nume", password='parola')
client.loop_start()
client.connect('127.0.0.1', 1883, 60)
time.sleep(15)
client.subscribe('Toopic', qos=1)
client.publish('Toopic', 'Published')

client.loop_stop()
client.disconnect()
