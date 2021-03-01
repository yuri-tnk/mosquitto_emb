/*

Copyright © 2004,2021 Yuri Tiomkin
All rights reserved.

Permission to use, copy, modify, and distribute this software in source
and binary forms and its documentation for any purpose and without fee
is hereby granted, provided that the above copyright notice appear
in all copies and that both that copyright notice and this permission
notice appear in supporting documentation.

THIS SOFTWARE IS PROVIDED BY THE YURI TIOMKIN AND CONTRIBUTORS ``AS IS'' AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL YURI TIOMKIN OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
SUCH DAMAGE.
*/

/*
Copyright (c) 2010-2014 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License v1.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   http://www.eclipse.org/legal/epl-v10.html
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.

Contributors:
   Roger Light - initial implementation and documentation.
*/

#ifndef _MOSQUITTO_INTERNAL_H_
#define _MOSQUITTO_INTERNAL_H_

//#include <config.h>
#include <time.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdint.h>
#include <stdint.h>
// YVT
#include <errno.h>
#include <sys/eventfd.h>


#include "mosquitto_emb.h"
#include "time_mosq.h"

#include "brssl.h"
#include "buf_iov.h"


typedef int mosq_sock_t;
typedef int mosq_eventfd_t;



enum mosquitto_msg_direction
{
	mosq_md_in = 0,
	mosq_md_out = 1
};

enum mosquitto_msg_state
{
	mosq_ms_invalid = 0,
	mosq_ms_publish_qos0 = 1,
	mosq_ms_publish_qos1 = 2,
	mosq_ms_wait_for_puback = 3,
	mosq_ms_publish_qos2 = 4,
	mosq_ms_wait_for_pubrec = 5,
	mosq_ms_resend_pubrel = 6,
	mosq_ms_wait_for_pubrel = 7,
	mosq_ms_resend_pubcomp = 8,
	mosq_ms_wait_for_pubcomp = 9,
	mosq_ms_send_pubrec = 10,
	mosq_ms_queued = 11
};

enum mosquitto_client_state
{
	mosq_cs_new = 0,
	mosq_cs_connected = 1,
	mosq_cs_disconnecting = 2,
	mosq_cs_connect_async = 3,
	mosq_cs_connect_pending = 4,
	mosq_cs_connect_srv = 5,
	mosq_cs_disconnect_ws = 6,
	mosq_cs_disconnected = 7,
	mosq_cs_socks5_new = 8,
	mosq_cs_socks5_start = 9,
	mosq_cs_socks5_request = 10,
	mosq_cs_socks5_reply = 11,
	mosq_cs_socks5_auth_ok = 12,
	mosq_cs_socks5_userpass_reply = 13,
	mosq_cs_socks5_send_userpass = 14,
	mosq_cs_expiring = 15,
};

enum mosquitto__protocol
{
	mosq_p_invalid = 0,
	mosq_p_mqtt31 = 1,
	mosq_p_mqtt311 = 2,
	mosq_p_mqtts = 3
};

enum mosquitto__transport
{
	mosq_t_invalid = 0,
	mosq_t_tcp = 1,
	mosq_t_ws = 2,
	mosq_t_sctp = 3
};

struct mosquitto__packet
{
	uint8_t *payload;
	struct mosquitto__packet *next;
	uint32_t remaining_mult;
	uint32_t remaining_length;
	uint32_t packet_length;
	uint32_t to_process;
	uint32_t pos;
	uint16_t mid;
	uint8_t command;
	int8_t remaining_count;
};

struct mosquitto_message_all
{
	struct mosquitto_message_all *next;
	time_t timestamp;
	//enum mosquitto_msg_direction direction;
	enum mosquitto_msg_state state;
	bool dup;
	struct mosquitto_message msg;
};



struct mosquitto
{
	mosq_sock_t sock;

//	mosq_sock_t sockpairR, sockpairW;
    mosq_eventfd_t efd; // YVT

	enum mosquitto__protocol protocol;
	char *address;
	char *id;
	char *username;
	char *password;
	uint16_t keepalive;
	uint16_t last_mid;
	enum mosquitto_client_state state;
	time_t last_msg_in;
	//time_t last_msg_out;
    time_t next_msg_out; 
	time_t ping_t;
	struct mosquitto__packet in_packet;
	struct mosquitto__packet *current_out_packet;
	struct mosquitto__packet *out_packet;
	struct mosquitto_message *will;

    //CERTSCTX cert_ctx;
    BEARSSL_SSL * ssl;
    int hsdetails;
    VLISTROOT vlist;
    int rx_drv_state;
    int tx_drv_state;
    int n_to_read;
    unsigned char * buf_to_read;

	char * ssl_cafile;
	char * ssl_cli_certfile;
	char * ssl_cli_keyfile;
    char * ssl_sni;
    char * srv_full_name;
    int verbose;
 

#if 0  // YVT
	SSL *ssl;
	SSL_CTX *ssl_ctx;
	char *tls_cafile;
	char *tls_capath;
	char *tls_certfile;
	char *tls_keyfile;
	int (*tls_pw_callback)(char *buf, int size, int rwflag, void *userdata);
	char *tls_version;
	char *tls_ciphers;
	char *tls_psk;
	char *tls_psk_identity;
	int tls_cert_reqs;
	bool tls_insecure;
#endif

	bool want_write;
	bool want_connect;

	pthread_mutex_t callback_mutex;
	pthread_mutex_t log_callback_mutex;
	pthread_mutex_t msgtime_mutex;
	pthread_mutex_t out_packet_mutex;
	pthread_mutex_t current_out_packet_mutex;
	pthread_mutex_t state_mutex;
	pthread_mutex_t in_message_mutex;
	pthread_mutex_t out_message_mutex;
	pthread_mutex_t mid_mutex;
	pthread_t thread_id;

	bool clean_session;
	void *userdata;
	bool in_callback;
	unsigned int message_retry;
	time_t last_retry_check;
	struct mosquitto_message_all *in_messages;
	struct mosquitto_message_all *in_messages_last;
	struct mosquitto_message_all *out_messages;
	struct mosquitto_message_all *out_messages_last;
	void (*on_connect)(struct mosquitto *, void *userdata, int rc);
	void (*on_disconnect)(struct mosquitto *, void *userdata, int rc);
	void (*on_publish)(struct mosquitto *, void *userdata, int mid);
	void (*on_message)(struct mosquitto *, void *userdata, const struct mosquitto_message *message);
	void (*on_subscribe)(struct mosquitto *, void *userdata, int mid, int qos_count, const int *granted_qos);
	void (*on_unsubscribe)(struct mosquitto *, void *userdata, int mid);
	void (*on_log)(struct mosquitto *, void *userdata, int level, const char *str);
	//void (*on_error)();

	char *host;
	uint16_t port;
	char *bind_address;
	unsigned int reconnects;
	unsigned int reconnect_delay;
	unsigned int reconnect_delay_max;
	bool reconnect_exponential_backoff;
	char threaded;


	int in_queue_len;
	int out_queue_len;
	struct mosquitto__packet *out_packet_last;
	int inflight_messages;
	int max_inflight_messages;
};

#define STREMPTY(str) (str[0] == '\0')

// YVT
int proc_ssl_engine_last_err(struct mosquitto * mosq);
int is_ssl_pending(struct mosquitto * mosq);
int mosquitto__set_state(struct mosquitto * mosq,
                         enum mosquitto_client_state state);
enum mosquitto_client_state mosquitto__get_state(struct mosquitto * mosq);

int mosquitto__create_eventfd(mosq_eventfd_t * efd_val);
int mosquitto__signal_eventfd(mosq_eventfd_t efd);
int mosquitto__clear_eventfd(mosq_eventfd_t efd);

static inline void set_errno(int err_no)
{
    errno = err_no;
}

#endif
