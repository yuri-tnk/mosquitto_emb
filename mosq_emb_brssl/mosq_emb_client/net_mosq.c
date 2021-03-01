/*
Copyright (c) 2009-2014 Roger Light <roger@atchoo.org>

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

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>


//#include <openssl/conf.h>
//#include <openssl/engine.h>
//#include <openssl/err.h>
//#include <tls_mosq.h>

#include "logging_mosq.h"
#include "memory_mosq.h"
#include "mqtt3_protocol.h"
#include "net_mosq.h"
#include "time_mosq.h"
#include "util_mosq.h"
#include "read_handle.h"

int tls_ex_index_mosq = -1;

int do_client_init(BEARSSL_SSL * ssl,
                   char * server_name_a, // name:port i.e '127.0.0.1:8883'
                   int verbose_a,
                   char * sni_a,
                   char * ca_name,
                   char * cert_name,
                   char * key_name,
                   int fd );

#define s_write write
//----------------------------------------------------------------------------
void mosquitto__net_init(void)
{
#if 0 // YVT

    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    if(tls_ex_index_mosq == -1)
    {
        tls_ex_index_mosq = SSL_get_ex_new_index(0, "client context", NULL, NULL, NULL);
    }
#endif
}

//----------------------------------------------------------------------------
void mosquitto__net_cleanup(void)
{
#if 0 // YVT
    ERR_remove_state(0);
    ENGINE_cleanup();
    CONF_modules_unload(1);
    ERR_free_strings();
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
#endif

}

//----------------------------------------------------------------------------
void mosquitto__packet_cleanup(struct mosquitto__packet *packet)
{
    if(packet == NULL)
        return;

    /* Free data and reset values */
    packet->command = 0;
    packet->remaining_count = 0;
    packet->remaining_mult = 1;
    packet->remaining_length = 0;
    if(packet->payload)
        mosquitto__free(packet->payload);
    packet->payload = NULL;
    packet->to_process = 0;
    packet->pos = 0;
}

//----------------------------------------------------------------------------
int mosquitto__packet_queue(struct mosquitto * mosq,
                            struct mosquitto__packet * packet)
{
    assert(mosq);
    assert(packet);

    packet->pos = 0;
    packet->to_process = packet->packet_length;

    packet->next = NULL;

    pthread_mutex_lock(&mosq->out_packet_mutex);
    if(mosq->out_packet)
    {
        mosq->out_packet_last->next = packet;
    }
    else
    {
        mosq->out_packet = packet;
    }
    mosq->out_packet_last = packet;
    pthread_mutex_unlock(&mosq->out_packet_mutex);

    /* Write a single byte to sockpairW (connected to sockpairR) to break out
     * of select() if in threaded mode. */

    if(mosq->efd != INVALID_SOCKET)           // YVT
    {
        mosquitto__signal_eventfd(mosq->efd);
    }

    return MOSQ_ERR_SUCCESS;
}

/* Close a socket associated with a context and set it to -1.
 * Returns 1 on failure (context is NULL)
 * Returns 0 on success.
 */

//----------------------------------------------------------------------------
int mosquitto__socket_close(struct mosquitto *mosq)
{
    int rc = 0;

    assert(mosq);

#if 0 // YVT

    if(mosq->ssl)
    {

        SSL_shutdown(mosq->ssl);
        SSL_free(mosq->ssl);
        mosq->ssl = NULL;
    }
    if(mosq->ssl_ctx)
    {
        SSL_CTX_free(mosq->ssl_ctx);
        mosq->ssl_ctx = NULL;
    }

    if((int)mosq->sock >= 0)
    {
        rc = COMPAT_CLOSE(mosq->sock);
        mosq->sock = INVALID_SOCKET;
    }
#endif

    return rc;
}

//----------------------------------------------------------------------------
int mosquitto__try_connect(struct mosquitto * mosq,
                           const char * host,
                           uint16_t port,
                           mosq_sock_t * sock,
                           const char * bind_address,
                           bool blocking)
{
    struct addrinfo hints;
    struct addrinfo *ainfo, *rp;
    struct addrinfo *ainfo_bind, *rp_bind;
    int s;
    int rc = MOSQ_ERR_SUCCESS;

    *sock = INVALID_SOCKET;
    memset(&hints, 0, sizeof(struct addrinfo));

    hints.ai_family   = PF_INET;  // Now we work with IPv4 only
    hints.ai_flags    = AI_ADDRCONFIG;
    hints.ai_socktype = SOCK_STREAM;

    s = getaddrinfo(host, NULL, &hints, &ainfo);
    if(s)
    {
        errno = s;
        return MOSQ_ERR_EAI;
    }

    if(bind_address != NULL)
    {
        s = getaddrinfo(bind_address, NULL, &hints, &ainfo_bind);
        if(s)
        {
            freeaddrinfo(ainfo);
            errno = s;
            return MOSQ_ERR_EAI;
        }
    }

    for(rp = ainfo; rp != NULL; rp = rp->ai_next)
    {
        *sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if(*sock == INVALID_SOCKET)
        {
            continue;
        }

        if(rp->ai_family == PF_INET)  // YVT We use IPv4 only here
        {
            ((struct sockaddr_in *)rp->ai_addr)->sin_port = htons(port);
        }
        else
        {
            COMPAT_CLOSE(*sock);
            continue;
        }

        if(bind_address != NULL)
        {
            for(rp_bind = ainfo_bind; rp_bind != NULL; rp_bind = rp_bind->ai_next)
            {
                if(bind(*sock, rp_bind->ai_addr, rp_bind->ai_addrlen) == 0)
                {
                    break;
                }
            }
            if(!rp_bind)
            {
                COMPAT_CLOSE(*sock);
                continue;
            }
        }

        if(!blocking)
        {
            /* Set non-blocking */
            if(mosquitto__socket_nonblock(*sock))
            {
                COMPAT_CLOSE(*sock);
                continue;
            }
        }

        //u_printf("port: %d\n", ntohs(((struct sockaddr_in *)rp->ai_addr)->sin_port));
        //exit(0);

        rc = connect(*sock, rp->ai_addr, rp->ai_addrlen);
        if(rc == 0 || errno == EINPROGRESS || errno == COMPAT_EWOULDBLOCK)
        {
            if(rc < 0 && (errno == EINPROGRESS || errno == COMPAT_EWOULDBLOCK))
            {
                rc = MOSQ_ERR_CONN_PENDING;
            }

            if(blocking)
            {
                /* Set non-blocking */
                if(mosquitto__socket_nonblock(*sock))
                {
                    COMPAT_CLOSE(*sock);
                    continue;
                }
            }
            break;
        }

        COMPAT_CLOSE(*sock);
        *sock = INVALID_SOCKET;
    }
    freeaddrinfo(ainfo);
    if(bind_address)
    {
        freeaddrinfo(ainfo_bind);
    }
    if(rp == NULL)
    {
        return MOSQ_ERR_ERRNO;
    }
    return rc;
}

/* Create a socket and connect it to 'ip' on port 'port'.
 * Returns -1 on failure (ip is NULL, socket creation/connection error)
 * Returns sock number on success.
 */

//----------------------------------------------------------------------------
int mosquitto__socket_connect(struct mosquitto *mosq,
                              const char * host,
                              uint16_t port,
                              const char * bind_address,
                              bool blocking)
{
#define BUF_LEN 128

    mosq_sock_t sock = INVALID_SOCKET;
    int rc = -1;

    if(mosq == NULL || host == NULL || port == 0)
    {
        return MOSQ_ERR_INVAL;
    }

    // connect regular TCP socket

    rc = mosquitto__try_connect(mosq, host, port, &sock, bind_address, blocking);
u_printf("mosquitto__try_connect: %d\n", rc);
    if(rc > 0)  // Case MOSQ_ERR_CONN_PENDING == -1  YVT
    {
        return rc;
    }

    if(mosq->ssl_cafile != NULL || mosq->ssl_cli_certfile != NULL ||
        mosq->ssl_cli_keyfile != NULL)
    {
        //-- Now - do SSL init and start SSL connection
u_printf("Connect SSL\n");
          // alloc SSL memory

        mosq->ssl = mosquitto__malloc(sizeof(BEARSSL_SSL));
        if(mosq->ssl == NULL)
        {
            return MOSQ_ERR_NOMEM;
        }
        memset(mosq->ssl, 0, sizeof(BEARSSL_SSL));

        mosq->srv_full_name = mosquitto__malloc(BUF_LEN);
        if(mosq->srv_full_name == NULL)
        {
            mosquitto__free(mosq->ssl);
            mosq->ssl = NULL;

            return MOSQ_ERR_NOMEM;
        }


        mosq->sock = sock;

        snprintf(mosq->srv_full_name, BUF_LEN, "%s:%d", host, port);

        do_client_init(mosq->ssl,
                       mosq->srv_full_name,    //(char*)g_srv,// char * server_name_a, // name:port i.e '127.0.0.1:8883'
                       mosq->verbose,          //int verbose_a,
                       mosq->ssl_sni,          //char * sni_a,
                       mosq->ssl_cafile,       //(char*)g_ca_name,
                       mosq->ssl_cli_certfile, //(char*)g_cert_name,
                       mosq->ssl_cli_keyfile,  //(char*)g_key_name,
                       sock);

        mosq->want_write   = true;
        mosq->want_connect = true;
    }
    else
    {
        mosq->sock = sock;
    }
    // ToDo - check extended errors
    return 0; // OK
}

//----------------------------------------------------------------------------
int mosquitto__read_byte(struct mosquitto__packet * packet,
                         uint8_t *byte)
{
    assert(packet);
    if(packet->pos+1 > packet->remaining_length)
        return MOSQ_ERR_PROTOCOL;

    *byte = packet->payload[packet->pos];
    packet->pos++;

    return MOSQ_ERR_SUCCESS;
}

//----------------------------------------------------------------------------
void mosquitto__write_byte(struct mosquitto__packet *packet,
                           uint8_t byte)
{
    assert(packet);
    assert(packet->pos+1 <= packet->packet_length);

    packet->payload[packet->pos] = byte;
    packet->pos++;
}

//----------------------------------------------------------------------------
int mosquitto__read_bytes(struct mosquitto__packet *packet,
                          void *bytes,
                          uint32_t count)
{
    assert(packet);
    if(packet->pos+count > packet->remaining_length)
        return MOSQ_ERR_PROTOCOL;

    memcpy(bytes, &(packet->payload[packet->pos]), count);
    packet->pos += count;

    return MOSQ_ERR_SUCCESS;
}

//----------------------------------------------------------------------------
void mosquitto__write_bytes(struct mosquitto__packet *packet,
                            const void *bytes,
                            uint32_t count)
{
    assert(packet);
    assert(packet->pos+count <= packet->packet_length);

    memcpy(&(packet->payload[packet->pos]), bytes, count);
    packet->pos += count;
}

//----------------------------------------------------------------------------
int mosquitto__read_string(struct mosquitto__packet *packet,
                           char **str)
{
    uint16_t len;
    int rc;

    assert(packet);
    rc = mosquitto__read_uint16(packet, &len);
    if(rc != 0)
        return rc;

    if(packet->pos+len > packet->remaining_length)
        return MOSQ_ERR_PROTOCOL;

    *str = mosquitto__malloc(len+1);
    if(*str)
    {
        memcpy(*str, &(packet->payload[packet->pos]), len);
        (*str)[len] = '\0';
        packet->pos += len;
    }
    else
    {
        return MOSQ_ERR_NOMEM;
    }

    return MOSQ_ERR_SUCCESS;
}

//----------------------------------------------------------------------------
void mosquitto__write_string(struct mosquitto__packet *packet,
                             const char *str,
                             uint16_t length)
{
    assert(packet);
    mosquitto__write_uint16(packet, length);
    mosquitto__write_bytes(packet, str, length);
}

//----------------------------------------------------------------------------
int mosquitto__read_uint16(struct mosquitto__packet *packet,
                           uint16_t *word)
{
    uint8_t msb, lsb;

    assert(packet);
    if(packet->pos + 2 > packet->remaining_length)
        return MOSQ_ERR_PROTOCOL;

    msb = packet->payload[packet->pos];
    packet->pos++;
    lsb = packet->payload[packet->pos];
    packet->pos++;

    *word = (msb<<8) + lsb;

    return MOSQ_ERR_SUCCESS;
}

//----------------------------------------------------------------------------
void mosquitto__write_uint16(struct mosquitto__packet *packet,
                             uint16_t word)
{
    mosquitto__write_byte(packet, MOSQ_MSB(word));
    mosquitto__write_byte(packet, MOSQ_LSB(word));
}


//----------------------------------------------------------------------------
int is_ssl_pending(struct mosquitto * mosq)
{
    unsigned int st;
    int rc = false;
    br_ssl_client_context * cc  = NULL;
    br_ssl_engine_context * eng = NULL;

    if(mosq != NULL && mosq->ssl != NULL && mosq->sock != INVALID_SOCKET)
    {
        cc = &mosq->ssl->cc;
        eng = &cc->eng;

        st = br_ssl_engine_current_state(eng);
        if(st & BR_SSL_RECVAPP)
        {
            rc = true;
        }
    }
    return rc;
}

void do_client_disconnect(struct mosquitto *mosq,
                          int reason_code)
                         // const mosquitto_property *properties)
{
	mosquitto__set_state(mosq, mosq_cs_disconnected);
	mosquitto__socket_close(mosq);

	/* Free data and reset values */
	pthread_mutex_lock(&mosq->out_packet_mutex);
	mosq->current_out_packet = mosq->out_packet;
	if(mosq->out_packet)
	{
		mosq->out_packet = mosq->out_packet->next;
		if(mosq->out_packet == NULL)
		{
			mosq->out_packet_last = NULL;
		}
	}
	pthread_mutex_unlock(&mosq->out_packet_mutex);

	pthread_mutex_lock(&mosq->msgtime_mutex);
	mosq->next_msg_out = mosquitto_time() + mosq->keepalive;
	pthread_mutex_unlock(&mosq->msgtime_mutex);

	pthread_mutex_lock(&mosq->callback_mutex);
	if(mosq->on_disconnect)
	{
		mosq->in_callback = true;
		mosq->on_disconnect(mosq, mosq->userdata, reason_code);
		mosq->in_callback = false;
	}
	pthread_mutex_unlock(&mosq->callback_mutex);

	pthread_mutex_unlock(&mosq->current_out_packet_mutex);
}

//----------------------------------------------------------------------------
int mosquitto__socket_nonblock(mosq_sock_t sock)
{

    int opt;
    /* Set non-blocking */
    opt = fcntl(sock, F_GETFL, 0);
    if(opt == -1)
    {
        COMPAT_CLOSE(sock);
        return 1;
    }
    if(fcntl(sock, F_SETFL, opt | O_NONBLOCK) == -1)
    {
        /* If either fcntl fails, don't want to allow this client to connect. */
        COMPAT_CLOSE(sock);
        return 1;
    }

    return 0;
}

//----------------------------------------------------------------------------
//----------------------------------------------------------------------------
//----------------------------------------------------------------------------
//----------------------------------------------------------------------------
//----------------------------------------------------------------------------


