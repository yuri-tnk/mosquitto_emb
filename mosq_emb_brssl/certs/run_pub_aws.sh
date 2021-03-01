mosquitto_pub -h a2dujmi05ideo2.iot.us-west-2.amazonaws.com -p 8883  \
 -t '$aws/things/demoDevice/shadow/update/delta'  -q 1 -d \
 --cafile /mnt/hgfs/Linux_shared/mosq_emb_brssl/certs/aws_ca.crt \
 --key /mnt/hgfs/Linux_shared/mosq_emb_brssl/certs/aws_cli_key.key \
 --cert /mnt/hgfs/Linux_shared/mosq_emb_brssl/certs/aws_cli_cert.crt \
 -m "This is a pretty long message from the pub."

# --cafile /home/yurit/Projects/mosquitto_emb/mosq_emb_brssl/certs/serverca.crt \
# --key /home/yurit/Projects/mosquitto_emb/mosq_emb_brssl/certs/client.key \
# --cert /home/yurit/Projects/mosquitto_emb/mosq_emb_brssl/certs/client.crt \

# --cafile /home/yurit/Projects/paho/mosquitto_conn_to_aws/local_root_ca.pem \
# --cert /home/yurit/Projects/paho/mosquitto_conn_to_aws/local_dev_cert.pem \
# --key /home/yurit/Projects/paho/mosquitto_conn_to_aws/local_dev_priv_key.pem \
