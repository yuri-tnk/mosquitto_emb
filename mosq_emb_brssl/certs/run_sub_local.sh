mosquitto_sub -h 127.0.0.1 -p 8883 -t em/qaz --insecure  -v -d  \
 --cafile /home/yurit/Projects/mosquitto_emb/mosq_emb_brssl/certs/serverca.crt \
 --key /home/yurit/Projects/mosquitto_emb/mosq_emb_brssl/certs/client.key \
 --cert /home/yurit/Projects/mosquitto_emb/mosq_emb_brssl/certs/client.crt



# --cafile /mnt/hgfs/Linux_shared/mosq_emb_bssl/certs/serverca.crt \
# --cert /mnt/hgfs/Linux_shared/mosq_emb_bssl/certs/client.crt \
# --key /mnt/hgfs/Linux_shared/mosq_emb_bssl/certs/client.key

# --cafile /home/yurit/Projects/paho/mosquitto_conn_to_aws/local_root_ca.pem \
# --cert /home/yurit/Projects/paho/mosquitto_conn_to_aws/local_dev_cert.pem \
# --key /home/yurit/Projects/paho/mosquitto_conn_to_aws/local_dev_priv_key.pem
