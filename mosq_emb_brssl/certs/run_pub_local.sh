mosquitto_pub -h 127.0.0.1 -p 8883 -t em/zaq --insecure -q 2 -d \
 --cafile /home/yurit/Projects/mosquitto_emb/mosq_emb_brssl/certs/serverca.crt \
 --key /home/yurit/Projects/mosquitto_emb/mosq_emb_brssl/certs/client.key \
 --cert /home/yurit/Projects/mosquitto_emb/mosq_emb_brssl/certs/client.crt \
 -m "This is a pretty long message from the pub. Also some ad-on - dont worry, be happy!"

# --cafile /home/yurit/Projects/paho/mosquitto_conn_to_aws/local_root_ca.pem \
# --cert /home/yurit/Projects/paho/mosquitto_conn_to_aws/local_dev_cert.pem \
# --key /home/yurit/Projects/paho/mosquitto_conn_to_aws/local_dev_priv_key.pem \
