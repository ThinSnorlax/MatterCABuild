import paho.mqtt.client as mqtt
import boto3
import json
import ssl
import time

# 亚马逊Root证书
ca_path = "./AmazonRootCA1.pem"
# 证书保存地址
cert_path = "./dac-chain.crt"
# 证书密钥保存地址
key_path = "./elsenow-ecc.key"
# IoT Core Endpoint
iot_core_endpoint = ""
# 收发消息的mqtt topic
mqtt_topic = '/iot/test/ttt'
# mqtt 连接的client id
client_id = 'snx-mqtt-client'
send_data_temp = {
            "device_id": client_id,
            "timestamp": int(time.time()),
            "awsomeday": "tttt"
        }


def on_connect(client, userdata, flags, rc):
    print("rc:", rc)
    print("session present:", flags['session present'])


def on_connect_fail(client, userdata, flags, rc):
    print(flags, rc)


def on_message(client, userdata, msg):
    print('已收到消息：', msg.payload.decode())


def on_disconn(client, userdata, rc):
    print("return code:", rc)
    if rc != 0:
        print("Unexpected MQTT disconnection. Attempting to reconnect.")
        try:
            client.reconnect()
        except BaseException as e:
            print(e)


def on_log(client, userdata, level, buf):
    print("log:{}".format(buf), level)


if __name__ == '__main__':
    aws_iot = boto3.client('iot')
    response = aws_iot.describe_endpoint()
    iot_core_endpoint = response['endpointAddress']
    mqtt_client = mqtt.Client(client_id=client_id, clean_session=False)
    mqtt_client.on_connect = on_connect
    mqtt_client.on_message = on_message
    mqtt_client.on_connect_fail = on_connect_fail
    mqtt_client.on_disconnect = on_disconn
    # mqtt_client.on_log = on_log
    mqtt_client.tls_set(ca_path,
                certfile=cert_path,
                keyfile=key_path,
                cert_reqs=ssl.CERT_REQUIRED,
                tls_version=ssl.PROTOCOL_TLSv1_2,
                ciphers=None)

    result_of_connection = mqtt_client.connect(iot_core_endpoint, 8883)
    if result_of_connection == 0:
        #print('connect success')
        print(result_of_connection)
    mqtt_client.loop_start()
    # while True:
    date_time = int(time.time())
    send_data = send_data_temp
    send_data['timestamp'] = date_time
    res = mqtt_client.publish(mqtt_topic, payload=json.dumps(send_data), qos=1)


