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
#ifndef _NET_MOSQ_H_
#define _NET_MOSQ_H_

#include <unistd.h>

#include "mosquitto_internal.h"
#include "mosquitto_emb.h"


#define COMPAT_CLOSE(a)    close(a)
#define COMPAT_ECONNRESET  ECONNRESET
#define COMPAT_EWOULDBLOCK EWOULDBLOCK

/* For when not using winsock libraries. */
#ifndef INVALID_SOCKET
#define INVALID_SOCKET -1
#endif

/* Macros for accessing the MSB and LSB of a uint16_t */
#define MOSQ_MSB(A) (uint8_t)((A & 0xFF00) >> 8)
#define MOSQ_LSB(A) (uint8_t)(A & 0x00FF)

void mosquitto__net_init(void);
void mosquitto__net_cleanup(void);

void mosquitto__packet_cleanup(struct mosquitto__packet *packet);
int mosquitto__packet_queue(struct mosquitto *mosq, struct mosquitto__packet *packet);
int mosquitto__socket_connect(struct mosquitto *mosq, const char *host, uint16_t port, const char *bind_address, bool blocking);
int mosquitto__socket_close(struct mosquitto *mosq);

int mosquitto__try_connect(struct mosquitto *mosq, const char *host, uint16_t port, mosq_sock_t *sock, const char *bind_address, bool blocking);
int mosquitto__socket_nonblock(mosq_sock_t sock);

int mosquitto__socketpair(mosq_eventfd_t * netfdRW);

int mosquitto__read_byte(struct mosquitto__packet *packet, uint8_t *byte);
int mosquitto__read_bytes(struct mosquitto__packet *packet, void *bytes, uint32_t count);
int mosquitto__read_string(struct mosquitto__packet *packet, char **str);
int mosquitto__read_uint16(struct mosquitto__packet *packet, uint16_t *word);

void mosquitto__write_byte(struct mosquitto__packet *packet, uint8_t byte);
void mosquitto__write_bytes(struct mosquitto__packet *packet, const void *bytes, uint32_t count);
void mosquitto__write_string(struct mosquitto__packet *packet, const char *str, uint16_t length);
void mosquitto__write_uint16(struct mosquitto__packet *packet, uint16_t word);

// YVT
//ssize_t mosquitto__net_read(struct mosquitto *mosq, void *buf, size_t count);
//ssize_t mosquitto__net_write(struct mosquitto *mosq, void *buf, size_t count);
ssize_t mosquitto__net_read_ex(struct mosquitto *mosq, void *buf, size_t count);
ssize_t mosquitto__net_write_ex(struct mosquitto *mosq, void *buf, size_t count);

int mosquitto__packet_write(struct mosquitto *mosq);
int mosquitto__packet_read(struct mosquitto *mosq);
// YVT
int mosquitto__signal_eventfd(mosq_eventfd_t efd);
int mosquitto__clear_eventfd(mosq_eventfd_t efd);


//#ifdef WITH_TLS
int mosquitto__socket_apply_tls(struct mosquitto *mosq);
int mosquitto__socket_connect_tls(struct mosquitto *mosq, int mode);
//#endif

#endif
