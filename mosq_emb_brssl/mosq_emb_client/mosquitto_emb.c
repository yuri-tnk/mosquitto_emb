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

#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>
#include <poll.h>  // YVT


#include "mosquitto_emb.h"
#include "mosquitto_internal.h"
#include "logging_mosq.h"
#include "messages_mosq.h"
#include "memory_mosq.h"
#include "mqtt3_protocol.h"
#include "net_mosq.h"
#include "read_handle.h"
#include "send_mosq.h"
//#include "socks_mosq.h"
#include "time_mosq.h"
//#include <tls_mosq.h>
#include "util_mosq.h"
#include "will_mosq.h"


//#include "config.h"

void mosquitto__destroy(struct mosquitto *mosq);
static int mosquitto__reconnect(struct mosquitto *mosq, bool blocking);
static int mosquitto__connect_init(struct mosquitto *mosq, const char *host, int port, int keepalive, const char *bind_address);

void * mosquitto_thread_main_func(void * par);
int do_rx_tx(struct mosquitto * mosq, int timeout);

//----------------------------------------------------------------------------
int mosquitto_loop_start(struct mosquitto *mosq)
{
    if(mosq == NULL || mosq->threaded == true)
    {
        return MOSQ_ERR_INVAL;
    }

    mosq->threaded = true;

    pthread_create(&mosq->thread_id,
                   NULL,
                   mosquitto_thread_main_func,
                   mosq);

    return MOSQ_ERR_SUCCESS;
}

//----------------------------------------------------------------------------
int mosquitto_loop_stop(struct mosquitto *mosq)
{
    if(mosq == NULL || mosq->threaded == false)
    {
        return MOSQ_ERR_INVAL;
    }

    /* signal to break out of poll() in  main thread */

    if(mosq->efd != INVALID_SOCKET)
    {
        mosquitto__signal_eventfd(mosq->efd);
    }

    pthread_join(mosq->thread_id, NULL);
    mosq->thread_id = pthread_self();

    mosq->threaded = false;

    return MOSQ_ERR_SUCCESS;
}


//----------------------------------------------------------------------------
void * mosquitto_thread_main_func(void * par)
{
    struct mosquitto * mosq = (struct mosquitto *)par;

    if(mosq == NULL)
    {
        return NULL;
    }

    pthread_mutex_lock(&mosq->state_mutex);

    //u_printf("Enter\n");
    if(mosq->state == mosq_cs_connect_async)
    {

        pthread_mutex_unlock(&mosq->state_mutex);
        u_printf("mosquitto_reconnect\n");
        mosquitto_reconnect(mosq);
    }
    else
    {
        pthread_mutex_unlock(&mosq->state_mutex);
    }

    if(mosq->keepalive == 0)
    {
        /* Sleep for a day if keepalive disabled. */
        mosquitto_loop_forever(mosq, 1000*86400, 1);

    }
    else
    {
        /* Sleep for our keepalive value. publish() etc. will wake us up. */

        mosquitto_loop_forever(mosq, mosq->keepalive * 1000, 1);
    }
u_printf("After loop_forever\n");
    return par;
}

//----------------------------------------------------------------------------
int mosquitto_lib_version(int *major, int *minor, int *revision)
{
    if(major)
        *major = LIBMOSQUITTO_MAJOR;
    if(minor)
        *minor = LIBMOSQUITTO_MINOR;
    if(revision)
        *revision = LIBMOSQUITTO_REVISION;
    return LIBMOSQUITTO_VERSION_NUMBER;
}

//----------------------------------------------------------------------------
int mosquitto_lib_init(void)
{
    struct timeval tv;

    gettimeofday(&tv, NULL);
    srand(tv.tv_sec*1000 + tv.tv_usec/1000);

    mosquitto__net_init();

    return MOSQ_ERR_SUCCESS;
}

//----------------------------------------------------------------------------
int mosquitto_lib_cleanup(void)
{
    mosquitto__net_cleanup();

    return MOSQ_ERR_SUCCESS;
}

//----------------------------------------------------------------------------
struct mosquitto * mosquitto_new(const char *id,
                                 bool clean_session,
                                 void *userdata)
{
    struct mosquitto *mosq = NULL;
    int rc;

    if(clean_session == false && id == NULL)
    {
        errno = EINVAL;
        return NULL;
    }

    signal(SIGPIPE, SIG_IGN);

    mosq = (struct mosquitto *)mosquitto__calloc(1, sizeof(struct mosquitto));
    if(mosq != NULL)
    {
        mosq->sock = INVALID_SOCKET;
        mosq->efd  = INVALID_SOCKET;
        // YVT mosq->sockpairR = INVALID_SOCKET;
        // YVT mosq->sockpairW = INVALID_SOCKET;

        mosq->thread_id = pthread_self();

        rc = mosquitto_reinitialise(mosq, id, clean_session, userdata);
        if(rc != 0)
        {
            mosquitto_destroy(mosq);
            if(rc == MOSQ_ERR_INVAL)
            {
                errno = EINVAL;
            }
            else if(rc == MOSQ_ERR_NOMEM)
            {
                errno = ENOMEM;
            }
            return NULL;
        }
    }
    else
    {
        errno = ENOMEM;
    }
    return mosq;
}

#if 0

int mosquitto_reinitialise(struct mosquitto *mosq, const char *id, bool clean_start, void *userdata)
{
    if(!mosq)
        return MOSQ_ERR_INVAL;

    if(clean_start == false && id == NULL)
    {
        return MOSQ_ERR_INVAL;
    }

    mosquitto__destroy(mosq);
    memset(mosq, 0, sizeof(struct mosquitto));

    if(userdata)
    {
        mosq->userdata = userdata;
    }
    else
    {
        mosq->userdata = mosq;
    }
    mosq->protocol = mosq_p_mqtt311;
    mosq->sock = INVALID_SOCKET;
    mosq->keepalive = 60;
    mosq->clean_start = clean_start;

    if(id)
    {
        if(STREMPTY(id))
        {
            return MOSQ_ERR_INVAL;
        }
        //if(mosquitto_validate_utf8(id, (int)strlen(id)))
        //{
        //  return MOSQ_ERR_MALFORMED_UTF8;
        //}
        mosq->id = mosquitto__strdup(id);
    }
    mosq->in_packet.payload = NULL;
    packet__cleanup(&mosq->in_packet);
    mosq->out_packet = NULL;
    mosq->current_out_packet = NULL;
    mosq->last_msg_in = mosquitto_time();
    mosq->next_msg_out = mosquitto_time() + mosq->keepalive;
    mosq->ping_t = 0;
    mosq->last_mid = 0;
    mosq->state = mosq_cs_new;
    mosq->max_qos = 2;
    mosq->msgs_in.inflight_maximum = 20;
    mosq->msgs_out.inflight_maximum = 20;
    mosq->msgs_in.inflight_quota = 20;
    mosq->msgs_out.inflight_quota = 20;
    mosq->will = NULL;
    mosq->on_connect = NULL;
    mosq->on_publish = NULL;
    mosq->on_message = NULL;
    mosq->on_subscribe = NULL;
    mosq->on_unsubscribe = NULL;
    mosq->host = NULL;
    mosq->port = 8883;
    mosq->in_callback = false;
    mosq->reconnect_delay = 1;
    mosq->reconnect_delay_max = 1;
    mosq->reconnect_exponential_backoff = false;
    mosq->threaded = mosq_ts_none;

#if 0  // YVT

#ifdef WITH_TLS
    mosq->ssl = NULL;
    mosq->ssl_ctx = NULL;
    mosq->tls_cert_reqs = SSL_VERIFY_PEER;
    mosq->tls_insecure = false;
    mosq->want_write = false;
    mosq->tls_ocsp_required = false;
#endif

#endif

    pthread_mutex_init(&mosq->callback_mutex, NULL);
    pthread_mutex_init(&mosq->log_callback_mutex, NULL);
    pthread_mutex_init(&mosq->state_mutex, NULL);
    pthread_mutex_init(&mosq->out_packet_mutex, NULL);
    pthread_mutex_init(&mosq->current_out_packet_mutex, NULL);
    pthread_mutex_init(&mosq->msgtime_mutex, NULL);
    pthread_mutex_init(&mosq->msgs_in.mutex, NULL);
    pthread_mutex_init(&mosq->msgs_out.mutex, NULL);
    pthread_mutex_init(&mosq->mid_mutex, NULL);

    mosq->thread_id = pthread_self();

    /* This must be after pthread_mutex_init(), otherwise the log mutex may be
     * used before being initialised. */

    if(net__socketpair(&mosq->sockpairR, &mosq->sockpairW))
    {
        log__printf(mosq, MOSQ_LOG_WARNING,
                "Warning: Unable to open socket pair, outgoing publish commands may be delayed.");
    }

    return MOSQ_ERR_SUCCESS;
}


void mosquitto__destroy(struct mosquitto *mosq)
{
    if(mosq == NULL)
    {
        return;
    }

    if(mosq->id)
    {
        /* If mosq->id is not NULL then the client has already been initialised
         * and so the mutexes need destroying. If mosq->id is NULL, the mutexes
         * haven't been initialised. */

        pthread_mutex_destroy(&mosq->callback_mutex);
        pthread_mutex_destroy(&mosq->log_callback_mutex);
        pthread_mutex_destroy(&mosq->state_mutex);
        pthread_mutex_destroy(&mosq->out_packet_mutex);
        pthread_mutex_destroy(&mosq->current_out_packet_mutex);
        pthread_mutex_destroy(&mosq->msgtime_mutex);
        pthread_mutex_destroy(&mosq->msgs_in.mutex);
        pthread_mutex_destroy(&mosq->msgs_out.mutex);
        pthread_mutex_destroy(&mosq->mid_mutex);
    }

    if(mosq->sock != INVALID_SOCKET)
    {
        net__socket_close(mosq);
    }

    message__cleanup_all(mosq);
    will__clear(mosq);

#if 0 // YVT
    if(mosq->ssl)
    {
        SSL_free(mosq->ssl);
    }
    if(mosq->ssl_ctx)
    {
        SSL_CTX_free(mosq->ssl_ctx);
    }

    mosquitto__free(mosq->tls_cafile);
    mosquitto__free(mosq->tls_capath);
    mosquitto__free(mosq->tls_certfile);
    mosquitto__free(mosq->tls_keyfile);
    if(mosq->tls_pw_callback)
        mosq->tls_pw_callback = NULL;
    mosquitto__free(mosq->tls_version);
    mosquitto__free(mosq->tls_ciphers);
    mosquitto__free(mosq->tls_psk);
    mosquitto__free(mosq->tls_psk_identity);
    mosquitto__free(mosq->tls_alpn);
#endif

    mosquitto__free(mosq->address);
    mosq->address = NULL;

    mosquitto__free(mosq->id);
    mosq->id = NULL;

    mosquitto__free(mosq->username);
    mosq->username = NULL;

    mosquitto__free(mosq->password);
    mosq->password = NULL;

    mosquitto__free(mosq->host);
    mosq->host = NULL;

    mosquitto__free(mosq->bind_address);
    mosq->bind_address = NULL;

    mosquitto_property_free_all(&mosq->connect_properties);

    packet__cleanup_all_no_locks(mosq);

    packet__cleanup(&mosq->in_packet);
    if(mosq->sockpairR != INVALID_SOCKET)
    {
        COMPAT_CLOSE(mosq->sockpairR);
        mosq->sockpairR = INVALID_SOCKET;
    }
    if(mosq->sockpairW != INVALID_SOCKET)
    {
        COMPAT_CLOSE(mosq->sockpairW);
        mosq->sockpairW = INVALID_SOCKET;
    }
}

//----------------------------------------------------------------------------
void mosquitto_destroy(struct mosquitto *mosq)
{
    if(mosq == NULL)
    {
        return;
    }

    mosquitto__destroy(mosq);
    mosquitto__free(mosq);
}

#endif

//----------------------------------------------------------------------------
int mosquitto_reinitialise(struct mosquitto *mosq,
                           const char *id,
                           bool clean_session,
                           void *userdata)
{
    int i;

    if(mosq == NULL)
        return MOSQ_ERR_INVAL;

    if(clean_session == false && id == NULL)
    {
        return MOSQ_ERR_INVAL;
    }

    mosquitto__destroy(mosq);

    memset(mosq, 0, sizeof(struct mosquitto));

    if(userdata)
    {
        mosq->userdata = userdata;
    }
    else
    {
        mosq->userdata = mosq;
    }
    mosq->protocol = mosq_p_mqtt31;
    mosq->sock = INVALID_SOCKET;
    mosq->efd  = INVALID_SOCKET;
// YVT    mosq->sockpairR = INVALID_SOCKET;
// YVT   mosq->sockpairW = INVALID_SOCKET;
    mosq->keepalive = 60;
    mosq->message_retry = 20;
    mosq->last_retry_check = 0;
    mosq->clean_session = clean_session;

    if(id)
    {
        if(STREMPTY(id))
        {
            return MOSQ_ERR_INVAL;
        }
        mosq->id = mosquitto__strdup(id);
    }
    else
    {
        mosq->id = (char *)mosquitto__calloc(24, sizeof(char));
        if(!mosq->id)
        {
            return MOSQ_ERR_NOMEM;
        }
        mosq->id[0] = 'm';
        mosq->id[1] = 'o';
        mosq->id[2] = 's';
        mosq->id[3] = 'q';
        mosq->id[4] = '/';

        for(i=5; i<23; i++)
        {
            mosq->id[i] = (rand()%73)+48;
        }
    }
    mosq->in_packet.payload = NULL;

    mosquitto__packet_cleanup(&mosq->in_packet);

    vlist_clear_all(&mosq->vlist);
    vlist_init(&mosq->vlist);
    mosq->rx_drv_state = 0;
    mosq->tx_drv_state = 0;

    mosq->out_packet = NULL;
    mosq->current_out_packet = NULL;
    mosq->last_msg_in = mosquitto_time();
    mosq->next_msg_out = mosquitto_time() + mosq->keepalive;
    mosq->ping_t = 0;
    mosq->last_mid = 0;
    mosq->state = mosq_cs_new;
    mosq->in_messages = NULL;
    mosq->in_messages_last = NULL;
    mosq->out_messages = NULL;
    mosq->out_messages_last = NULL;
    mosq->max_inflight_messages = 20;
    mosq->will = NULL;
    mosq->on_connect = NULL;
    mosq->on_publish = NULL;
    mosq->on_message = NULL;
    mosq->on_subscribe = NULL;
    mosq->on_unsubscribe = NULL;
    mosq->host = NULL;
    mosq->port = 1883;
    mosq->in_callback = false;
    mosq->in_queue_len = 0;
    mosq->out_queue_len = 0;
    mosq->reconnect_delay = 1;
    mosq->reconnect_delay_max = 1;
    mosq->reconnect_exponential_backoff = false;
    mosq->threaded = false;
//=====
#if 0 // YVT
    mosq->ssl = NULL;
    mosq->tls_cert_reqs = SSL_VERIFY_PEER;
    mosq->tls_insecure = false;
#endif
    mosq->want_write = false;


    pthread_mutex_init(&mosq->callback_mutex, NULL);
    pthread_mutex_init(&mosq->log_callback_mutex, NULL);
    pthread_mutex_init(&mosq->state_mutex, NULL);
    pthread_mutex_init(&mosq->out_packet_mutex, NULL);
    pthread_mutex_init(&mosq->current_out_packet_mutex, NULL);
    pthread_mutex_init(&mosq->msgtime_mutex, NULL);
    pthread_mutex_init(&mosq->in_message_mutex, NULL);
    pthread_mutex_init(&mosq->out_message_mutex, NULL);
    pthread_mutex_init(&mosq->mid_mutex, NULL);

    mosq->thread_id = pthread_self();

    //--- Create eventfd

    mosquitto__create_eventfd(&mosq->efd);

    return MOSQ_ERR_SUCCESS;
}

//----------------------------------------------------------------------------
int mosquitto_will_set(struct mosquitto *mosq,
                       const char *topic,
                       int payloadlen,
                       const void *payload,
                       int qos,
                       bool retain)
{
    if(!mosq)
        return MOSQ_ERR_INVAL;
    return mosquitto__will_set(mosq, topic, payloadlen, payload, qos, retain);
}

//----------------------------------------------------------------------------
int mosquitto_will_clear(struct mosquitto *mosq)
{
    if(!mosq)
        return MOSQ_ERR_INVAL;
    return mosquitto__will_clear(mosq);
}

//----------------------------------------------------------------------------
int mosquitto_username_pw_set(struct mosquitto *mosq, const char *username, const char *password)
{
    if(!mosq)
        return MOSQ_ERR_INVAL;

    if(mosq->username)
    {
        mosquitto__free(mosq->username);
        mosq->username = NULL;
    }
    if(mosq->password)
    {
        mosquitto__free(mosq->password);
        mosq->password = NULL;
    }

    if(username)
    {
        mosq->username = mosquitto__strdup(username);
        if(!mosq->username)
            return MOSQ_ERR_NOMEM;
        if(password)
        {
            mosq->password = mosquitto__strdup(password);
            if(!mosq->password)
            {
                mosquitto__free(mosq->username);
                mosq->username = NULL;
                return MOSQ_ERR_NOMEM;
            }
        }
    }
    return MOSQ_ERR_SUCCESS;
}

//----------------------------------------------------------------------------
int mosquitto_reconnect_delay_set(struct mosquitto * mosq,
                                  unsigned int reconnect_delay,
                                  unsigned int reconnect_delay_max,
                                  bool reconnect_exponential_backoff)
{
    if(!mosq)
        return MOSQ_ERR_INVAL;

    mosq->reconnect_delay = reconnect_delay;
    mosq->reconnect_delay_max = reconnect_delay_max;
    mosq->reconnect_exponential_backoff = reconnect_exponential_backoff;

    return MOSQ_ERR_SUCCESS;

}

//----------------------------------------------------------------------------
void mosquitto__destroy(struct mosquitto *mosq)
{
    struct mosquitto__packet *packet;
    if(!mosq)
        return;

    if(mosq->threaded && !pthread_equal(mosq->thread_id, pthread_self()))
    {
        pthread_cancel(mosq->thread_id);
        pthread_join(mosq->thread_id, NULL);
        mosq->threaded = false;
    }

    if(mosq->id)
    {
        /* If mosq->id is not NULL then the client has already been initialised
         * and so the mutexes need destroying. If mosq->id is NULL, the mutexes
         * haven't been initialised. */
        pthread_mutex_destroy(&mosq->callback_mutex);
        pthread_mutex_destroy(&mosq->log_callback_mutex);
        pthread_mutex_destroy(&mosq->state_mutex);
        pthread_mutex_destroy(&mosq->out_packet_mutex);
        pthread_mutex_destroy(&mosq->current_out_packet_mutex);
        pthread_mutex_destroy(&mosq->msgtime_mutex);
        pthread_mutex_destroy(&mosq->in_message_mutex);
        pthread_mutex_destroy(&mosq->out_message_mutex);
        pthread_mutex_destroy(&mosq->mid_mutex);
    }

    if(mosq->sock != INVALID_SOCKET)
    {
        mosquitto__socket_close(mosq);
    }
    mosquitto__message_cleanup_all(mosq);
    mosquitto__will_clear(mosq);

#if 0 // YVT
    if(mosq->ssl)
    {
        SSL_free(mosq->ssl);
    }
    if(mosq->ssl_ctx)
    {
        SSL_CTX_free(mosq->ssl_ctx);
    }
    if(mosq->tls_cafile)
        mosquitto__free(mosq->tls_cafile);
    if(mosq->tls_capath)
        mosquitto__free(mosq->tls_capath);
    if(mosq->tls_certfile)
        mosquitto__free(mosq->tls_certfile);
    if(mosq->tls_keyfile)
        mosquitto__free(mosq->tls_keyfile);
    if(mosq->tls_pw_callback)
        mosq->tls_pw_callback = NULL;
    if(mosq->tls_version)
        mosquitto__free(mosq->tls_version);
    if(mosq->tls_ciphers)
        mosquitto__free(mosq->tls_ciphers);
    if(mosq->tls_psk)
        mosquitto__free(mosq->tls_psk);
    if(mosq->tls_psk_identity)
        mosquitto__free(mosq->tls_psk_identity);
#endif

    if(mosq->address)
    {
        mosquitto__free(mosq->address);
        mosq->address = NULL;
    }
    if(mosq->id)
    {
        mosquitto__free(mosq->id);
        mosq->id = NULL;
    }
    if(mosq->username)
    {
        mosquitto__free(mosq->username);
        mosq->username = NULL;
    }
    if(mosq->password)
    {
        mosquitto__free(mosq->password);
        mosq->password = NULL;
    }
    if(mosq->host)
    {
        mosquitto__free(mosq->host);
        mosq->host = NULL;
    }
    if(mosq->bind_address)
    {
        mosquitto__free(mosq->bind_address);
        mosq->bind_address = NULL;
    }

    /* Out packet cleanup */
    if(mosq->out_packet && !mosq->current_out_packet)
    {
        mosq->current_out_packet = mosq->out_packet;
        mosq->out_packet = mosq->out_packet->next;
    }
    while(mosq->current_out_packet)
    {
        packet = mosq->current_out_packet;
        /* Free data and reset values */
        mosq->current_out_packet = mosq->out_packet;
        if(mosq->out_packet)
        {
            mosq->out_packet = mosq->out_packet->next;
        }

        mosquitto__packet_cleanup(packet);
        mosquitto__free(packet);
    }

    mosquitto__packet_cleanup(&mosq->in_packet);
#if 0 // YVT
    if(mosq->sockpairR != INVALID_SOCKET)
    {
        COMPAT_CLOSE(mosq->sockpairR);
        mosq->sockpairR = INVALID_SOCKET;
    }
    if(mosq->sockpairW != INVALID_SOCKET)
    {
        COMPAT_CLOSE(mosq->sockpairW);
        mosq->sockpairW = INVALID_SOCKET;
    }
#endif
}

//----------------------------------------------------------------------------
void mosquitto_destroy(struct mosquitto *mosq)
{
    if(!mosq)
        return;

    mosquitto__destroy(mosq);
    mosquitto__free(mosq);
}

//----------------------------------------------------------------------------
int mosquitto_socket(struct mosquitto *mosq)
{
    if(!mosq)
        return INVALID_SOCKET;
    return mosq->sock;
}

//----------------------------------------------------------------------------
static int mosquitto__connect_init(struct mosquitto *mosq,
                                   const char *host,
                                   int port,
                                   int keepalive,
                                   const char *bind_address)
{
    if(mosq == NULL)
        return MOSQ_ERR_INVAL;
    if(host== NULL || port <= 0)
        return MOSQ_ERR_INVAL;

    if(mosq->host != NULL)
        mosquitto__free(mosq->host);

    mosq->host = mosquitto__strdup(host);
    if(mosq->host == NULL)
        return MOSQ_ERR_NOMEM;

    mosq->port = port;

    if(mosq->bind_address != NULL)
        mosquitto__free(mosq->bind_address);

    if(bind_address != NULL)
    {
        mosq->bind_address = mosquitto__strdup(bind_address);

        if(mosq->bind_address == NULL)
            return MOSQ_ERR_NOMEM;
    }

    mosq->keepalive = keepalive;

#if 0 // YVT
    if(mosq->sockpairR != INVALID_SOCKET)
    {
        COMPAT_CLOSE(mosq->sockpairR);
        mosq->sockpairR = INVALID_SOCKET;
    }
    if(mosq->sockpairW != INVALID_SOCKET)
    {
        COMPAT_CLOSE(mosq->sockpairW);
        mosq->sockpairW = INVALID_SOCKET;
    }

    if(mosquitto__socketpair(&mosq->sockpairR, &mosq->sockpairW))
    {
        mosquitto__log_printf(mosq, MOSQ_LOG_WARNING,
                              "Warning: Unable to open socket pair, outgoing publish commands may be delayed.");
    }

#endif
    return MOSQ_ERR_SUCCESS;
}

//----------------------------------------------------------------------------
int mosquitto_connect(struct mosquitto *mosq,
                      const char *host,
                      int port,
                      int keepalive)
{
    return mosquitto_connect_bind(mosq, host, port, keepalive, NULL);
}

//----------------------------------------------------------------------------
int mosquitto_connect_bind(struct mosquitto *mosq,
                           const char *host,
                           int port,
                           int keepalive,
                           const char *bind_address)
{
    int rc;

    // Clear && reinit addr, recreate(if any) eventfile
    rc = mosquitto__connect_init(mosq, host, port, keepalive, bind_address);
    if(rc != 0)
    {
u_printf("1 rc: %d\n", rc);
        return rc;
    }

    pthread_mutex_lock(&mosq->state_mutex);
    mosq->state = mosq_cs_new;
    pthread_mutex_unlock(&mosq->state_mutex);

    return mosquitto__reconnect(mosq, true);
}

//----------------------------------------------------------------------------
int mosquitto_reconnect(struct mosquitto *mosq)
{
    return mosquitto__reconnect(mosq, true);
}

//----------------------------------------------------------------------------
static int mosquitto__reconnect(struct mosquitto *mosq, bool blocking)
{
    int rc;
    struct mosquitto__packet *packet;
    if(mosq == NULL)
        return MOSQ_ERR_INVAL;
    if(mosq->host == NULL || mosq->port <= 0)
        return MOSQ_ERR_INVAL;

    pthread_mutex_lock(&mosq->state_mutex);
    mosq->state = mosq_cs_new;
    pthread_mutex_unlock(&mosq->state_mutex);

    pthread_mutex_lock(&mosq->msgtime_mutex);
    mosq->last_msg_in  = mosquitto_time();
    mosq->next_msg_out = mosq->last_msg_in + mosq->keepalive;
    pthread_mutex_unlock(&mosq->msgtime_mutex);

    mosq->ping_t = 0;

    mosquitto__packet_cleanup(&mosq->in_packet);

    pthread_mutex_lock(&mosq->current_out_packet_mutex);
    pthread_mutex_lock(&mosq->out_packet_mutex);

    if(mosq->out_packet != NULL && mosq->current_out_packet == NULL)
    {
        mosq->current_out_packet = mosq->out_packet;
        mosq->out_packet = mosq->out_packet->next;
    }

    while(mosq->current_out_packet)
    {
        packet = mosq->current_out_packet;
        /* Free data and reset values */
        mosq->current_out_packet = mosq->out_packet;
        if(mosq->out_packet != NULL)
        {
            mosq->out_packet = mosq->out_packet->next;
        }

        mosquitto__packet_cleanup(packet);
        mosquitto__free(packet);
    }
    pthread_mutex_unlock(&mosq->out_packet_mutex);
    pthread_mutex_unlock(&mosq->current_out_packet_mutex);

    mosquitto__messages_reconnect_reset(mosq);

    rc = mosquitto__socket_connect(mosq,
                                   mosq->host,
                                   mosq->port,
                                   mosq->bind_address,
                                   blocking);
    if(rc > 0) // ???
    {
        return rc;
    }

    return mosquitto__send_connect(mosq, mosq->keepalive, mosq->clean_session);
}

//----------------------------------------------------------------------------
int mosquitto_disconnect(struct mosquitto *mosq)
{
    if(!mosq)
        return MOSQ_ERR_INVAL;

    pthread_mutex_lock(&mosq->state_mutex);
    mosq->state = mosq_cs_disconnecting;
    pthread_mutex_unlock(&mosq->state_mutex);

    if(mosq->sock == INVALID_SOCKET)
        return MOSQ_ERR_NO_CONN;
    return mosquitto__send_disconnect(mosq);
}

//----------------------------------------------------------------------------
int mosquitto_publish(struct mosquitto *mosq,
                      int *mid,
                      const char *topic,
                      int payloadlen,
                      const void *payload,
                      int qos,
                      bool retain)
{
    struct mosquitto_message_all *message;
    uint16_t local_mid;
    int queue_status;

    if(mosq == NULL || topic == NULL || qos < 0 || qos > 2)
        return MOSQ_ERR_INVAL;

    if(STREMPTY(topic))
        return MOSQ_ERR_INVAL;
    if(payloadlen < 0 || payloadlen > MQTT_MAX_PAYLOAD)
        return MOSQ_ERR_PAYLOAD_SIZE;

    if(mosquitto_pub_topic_check(topic) != MOSQ_ERR_SUCCESS)
    {
        return MOSQ_ERR_INVAL;
    }

    local_mid = mosquitto__mid_generate(mosq);
    if(mid)
    {
        *mid = local_mid;
    }

    if(qos == 0)
    {
        return mosquitto__send_publish(mosq, local_mid, topic, payloadlen, payload, qos, retain, false);
    }
    else
    {
        message = mosquitto__calloc(1, sizeof(struct mosquitto_message_all));
        if(!message)
            return MOSQ_ERR_NOMEM;

        message->next = NULL;
        message->timestamp = mosquitto_time();
        message->msg.mid = local_mid;
        message->msg.topic = mosquitto__strdup(topic);
        if(!message->msg.topic)
        {
            mosquitto__message_cleanup(&message);
            return MOSQ_ERR_NOMEM;
        }

        if(payloadlen)
        {
            message->msg.payloadlen = payloadlen;
            message->msg.payload = mosquitto__malloc(payloadlen*sizeof(uint8_t));
            if(!message->msg.payload)
            {
                mosquitto__message_cleanup(&message);
                return MOSQ_ERR_NOMEM;
            }
            memcpy(message->msg.payload, payload, payloadlen*sizeof(uint8_t));
        }
        else
        {
            message->msg.payloadlen = 0;
            message->msg.payload = NULL;
        }

        message->msg.qos = qos;
        message->msg.retain = retain;
        message->dup = false;

        pthread_mutex_lock(&mosq->out_message_mutex);
        queue_status = mosquitto__message_queue(mosq, message, mosq_md_out);
        if(queue_status == 0)
        {
            if(qos == 1)
            {
                message->state = mosq_ms_wait_for_puback;
            }
            else if(qos == 2)
            {
                message->state = mosq_ms_wait_for_pubrec;
            }
            pthread_mutex_unlock(&mosq->out_message_mutex);

            return mosquitto__send_publish(mosq,
                                           message->msg.mid,
                                           message->msg.topic,
                                           message->msg.payloadlen,
                                           message->msg.payload,
                                           message->msg.qos,
                                           message->msg.retain,
                                           message->dup);
        }
        else
        {
            message->state = mosq_ms_invalid;
            pthread_mutex_unlock(&mosq->out_message_mutex);
            return MOSQ_ERR_SUCCESS;
        }
    }
}

//----------------------------------------------------------------------------
int mosquitto_subscribe(struct mosquitto * mosq,
                        int * mid,
                        const char * sub,
                        int qos)
{
    if(!mosq)
        return MOSQ_ERR_INVAL;
    if(mosq->sock == INVALID_SOCKET)
        return MOSQ_ERR_NO_CONN;

    if(mosquitto_sub_topic_check(sub))
        return MOSQ_ERR_INVAL;

    return mosquitto__send_subscribe(mosq, mid, sub, qos);
}

//----------------------------------------------------------------------------
int mosquitto_unsubscribe(struct mosquitto * mosq,
                          int * mid,
                          const char * sub)
{
    if(!mosq)
        return MOSQ_ERR_INVAL;
    if(mosq->sock == INVALID_SOCKET)
        return MOSQ_ERR_NO_CONN;

    if(mosquitto_sub_topic_check(sub))
        return MOSQ_ERR_INVAL;

    return mosquitto__send_unsubscribe(mosq, mid, sub);
}

//----------------------------------------------------------------------------
int mosquitto_tls_set(struct mosquitto *mosq,
                      const char * cafile,
                      const char * capath,
                      const char * certfile,
                      const char *keyfile,
                      int (*pw_callback)(char *buf, int size, int rwflag, void *userdata))
{
#if 0 // YVT

    FILE *fptr;

    if(!mosq || (!cafile && !capath) || (certfile && !keyfile) || (!certfile && keyfile))
        return MOSQ_ERR_INVAL;

    if(cafile)
    {
        fptr = mosquitto__fopen(cafile, "rt");
        if(fptr)
        {
            fclose(fptr);
        }
        else
        {
            return MOSQ_ERR_INVAL;
        }
        mosq->tls_cafile = mosquitto__strdup(cafile);

        if(!mosq->tls_cafile)
        {
            return MOSQ_ERR_NOMEM;
        }
    }
    else if(mosq->tls_cafile)
    {
        mosquitto__free(mosq->tls_cafile);
        mosq->tls_cafile = NULL;
    }

    if(capath)
    {
        mosq->tls_capath = mosquitto__strdup(capath);
        if(!mosq->tls_capath)
        {
            return MOSQ_ERR_NOMEM;
        }
    }
    else if(mosq->tls_capath)
    {
        mosquitto__free(mosq->tls_capath);
        mosq->tls_capath = NULL;
    }

    if(certfile)
    {
        fptr = mosquitto__fopen(certfile, "rt");
        if(fptr)
        {
            fclose(fptr);
        }
        else
        {
            if(mosq->tls_cafile)
            {
                mosquitto__free(mosq->tls_cafile);
                mosq->tls_cafile = NULL;
            }
            if(mosq->tls_capath)
            {
                mosquitto__free(mosq->tls_capath);
                mosq->tls_capath = NULL;
            }
            return MOSQ_ERR_INVAL;
        }
        mosq->tls_certfile = mosquitto__strdup(certfile);
        if(!mosq->tls_certfile)
        {
            return MOSQ_ERR_NOMEM;
        }
    }
    else
    {
        if(mosq->tls_certfile)
            mosquitto__free(mosq->tls_certfile);
        mosq->tls_certfile = NULL;
    }

    if(keyfile)
    {
        fptr = mosquitto__fopen(keyfile, "rt");
        if(fptr)
        {
            fclose(fptr);
        }
        else
        {
            if(mosq->tls_cafile)
            {
                mosquitto__free(mosq->tls_cafile);
                mosq->tls_cafile = NULL;
            }
            if(mosq->tls_capath)
            {
                mosquitto__free(mosq->tls_capath);
                mosq->tls_capath = NULL;
            }
            if(mosq->tls_certfile)
            {
                mosquitto__free(mosq->tls_certfile);
                mosq->tls_certfile = NULL;
            }
            return MOSQ_ERR_INVAL;
        }
        mosq->tls_keyfile = mosquitto__strdup(keyfile);
        if(!mosq->tls_keyfile)
        {
            return MOSQ_ERR_NOMEM;
        }
    }
    else
    {
        if(mosq->tls_keyfile)
            mosquitto__free(mosq->tls_keyfile);
        mosq->tls_keyfile = NULL;
    }

    mosq->tls_pw_callback = pw_callback;
#endif
    return MOSQ_ERR_SUCCESS;
}

//----------------------------------------------------------------------------
int mosquitto_tls_opts_set(struct mosquitto * mosq,
                           int cert_reqs,
                           const char * tls_version,
                           const char * ciphers)
{

    if(!mosq)
        return MOSQ_ERR_INVAL;
#if 0 // YVT

    mosq->tls_cert_reqs = cert_reqs;
    if(tls_version)
    {
        if(!strcasecmp(tls_version, "tlsv1.2")
                || !strcasecmp(tls_version, "tlsv1.1")
                || !strcasecmp(tls_version, "tlsv1"))
        {

            mosq->tls_version = mosquitto__strdup(tls_version);
            if(!mosq->tls_version) return MOSQ_ERR_NOMEM;
        }
        else
        {
            return MOSQ_ERR_INVAL;
        }
    }
    else
    {
        mosq->tls_version = mosquitto__strdup("tlsv1.2");
        if(!mosq->tls_version)
            return MOSQ_ERR_NOMEM;
    }
    if(ciphers)
    {
        mosq->tls_ciphers = mosquitto__strdup(ciphers);
        if(!mosq->tls_ciphers)
            return MOSQ_ERR_NOMEM;
    }
    else
    {
        mosq->tls_ciphers = NULL;
    }
#endif// YVT

    return MOSQ_ERR_SUCCESS;
}

//----------------------------------------------------------------------------
int mosquitto_tls_insecure_set(struct mosquitto *mosq, bool value)
{

    if(!mosq)
        return MOSQ_ERR_INVAL;
#if 0 // YVT
    mosq->tls_insecure = value;
#endif
    return MOSQ_ERR_SUCCESS;
}


//----------------------------------------------------------------------------
int mosquitto_tls_psk_set(struct mosquitto *mosq, const char *psk, const char *identity, const char *ciphers)
{
    return MOSQ_ERR_NOT_SUPPORTED;
}

//----------------------------------------------------------------------------
static int interruptible_sleep(struct mosquitto * mosq, time_t reconnect_delay) /* time in sec */
{
    struct pollfd pfd[1];
    int rc;

    if(mosq == NULL || mosq->efd == INVALID_SOCKET || reconnect_delay <= 0)
        return MOSQ_ERR_INVAL;

    pfd[0].fd = mosq->efd;
    pfd[0].revents = 0;
    pfd[0].events  = POLLOUT;  //POLLIN | POLLERR;

    rc = poll(pfd, 1, reconnect_delay * 1000);
    if(rc < 0) // err
    {
        if(errno == EINTR)
        {
            return MOSQ_ERR_SUCCESS;
        }
        else
        {
            return MOSQ_ERR_ERRNO;
        }
    }
    else // include timeout
    {
        if(pfd[0].revents & POLLOUT)
        {
            mosquitto__clear_eventfd(mosq->efd);
        }
    }

    return MOSQ_ERR_SUCCESS;

#if 0 // YVT

    struct timeval local_timeout;

    fd_set readfds;
    int fdcount;
    char pairbuf;
    int maxfd = 0;

    local_timeout.tv_sec = reconnect_delay;
    local_timeout.tv_usec = 0;

    FD_ZERO(&readfds);
    maxfd = 0;
    if(mosq->sockpairR != INVALID_SOCKET)
    {
        /* sockpairR is used to break out of select() before the
         * timeout, when mosquitto_loop_stop() is called */
        FD_SET(mosq->sockpairR, &readfds);
        maxfd = mosq->sockpairR;
    }

    fdcount = select(maxfd+1, &readfds, NULL, NULL, &local_timeout);
    if(fdcount == -1)
    {
        if(errno == EINTR)
        {
            return MOSQ_ERR_SUCCESS;
        }
        else
        {
            return MOSQ_ERR_ERRNO;
        }
    }
    else if(mosq->sockpairR != INVALID_SOCKET && FD_ISSET(mosq->sockpairR, &readfds))
    {

        if(read(mosq->sockpairR, &pairbuf, 1) == 0)
        {
        }
    }
    return MOSQ_ERR_SUCCESS;
#endif
}

//----------------------------------------------------------------------------
int mosquitto_loop_forever(struct mosquitto *mosq, int timeout, int max_packets)
{
    int run = 1;
    int rc = MOSQ_ERR_SUCCESS;
    unsigned long reconnect_delay;
    enum mosquitto_client_state state;

    if(mosq == NULL)
    {
        return MOSQ_ERR_INVAL;
    }

    mosq->reconnects = 0;

    while(run)
    {
        do
        {
     //      rc = mosquitto_loop_ex(mosq, timeout, max_packets);
           rc = do_rx_tx(mosq, timeout);

        }while(run && rc == MOSQ_ERR_SUCCESS);

        /* Quit after fatal errors. */
u_printf("====== Leave do_tx_rx %d\n", rc);
        switch(rc)
        {
            case MOSQ_ERR_NOMEM:
            case MOSQ_ERR_PROTOCOL:
            case MOSQ_ERR_INVAL:
            case MOSQ_ERR_NOT_FOUND:
            case MOSQ_ERR_TLS:
            case MOSQ_ERR_PAYLOAD_SIZE:
            case MOSQ_ERR_NOT_SUPPORTED:
            case MOSQ_ERR_AUTH:
            case MOSQ_ERR_ACL_DENIED:
            case MOSQ_ERR_UNKNOWN:
            case MOSQ_ERR_EAI:
            case MOSQ_ERR_PROXY:
                return rc;

            case MOSQ_ERR_ERRNO:

                break;
        }

        if(errno == EPROTO)
        {
            return rc;
        }

        do
        {
            rc = MOSQ_ERR_SUCCESS;
            state = mosquitto__get_state(mosq);
            if(state == mosq_cs_disconnecting || state == mosq_cs_disconnected)
            {
                run = 0;
            }
            else
            {
                if(mosq->reconnect_delay_max > mosq->reconnect_delay)
                {
                    if(mosq->reconnect_exponential_backoff)
                    {
                        reconnect_delay = mosq->reconnect_delay*(mosq->reconnects+1)*(mosq->reconnects+1);
                    }
                    else
                    {
                        reconnect_delay = mosq->reconnect_delay*(mosq->reconnects+1);
                    }
                }
                else
                {
                    reconnect_delay = mosq->reconnect_delay;
                }

                if(reconnect_delay > mosq->reconnect_delay_max)
                {
                    reconnect_delay = mosq->reconnect_delay_max;
                }
                else
                {
                    mosq->reconnects++;
                }

                rc = interruptible_sleep(mosq, (time_t)reconnect_delay);
                if(rc != 0)
                {
                    return rc;
                }

                state = mosquitto__get_state(mosq);
                if(state == mosq_cs_disconnecting || state == mosq_cs_disconnected)
                {
                    run = 0;
                }
                else
                {
u_printf("Got reconnect\n");
                    rc = mosquitto_reconnect(mosq);
                }
            }
        }
        while(run && rc != MOSQ_ERR_SUCCESS);
    }
    return rc;
}

//----------------------------------------------------------------------------
int mosquitto_loop_misc(struct mosquitto *mosq)
{
    int rc;

    if(mosq == NULL)
    {
        rc = MOSQ_ERR_INVAL;
    }
    else if(mosq->sock == INVALID_SOCKET)
    {
        rc = MOSQ_ERR_NO_CONN;
    }
    else
    {
	    rc = mosquitto__check_keepalive(mosq);
	}
	return rc;
}

//----------------------------------------------------------------------------
int mosquitto_opts_set(struct mosquitto *mosq, enum mosq_opt_t option, void *value)
{
    int ival;

    if(!mosq || !value)
        return MOSQ_ERR_INVAL;

    switch(option)
    {
        case MOSQ_OPT_PROTOCOL_VERSION:
            ival = *((int *)value);
            if(ival == MQTT_PROTOCOL_V31)
            {
                mosq->protocol = mosq_p_mqtt31;
            }
            else if(ival == MQTT_PROTOCOL_V311)
            {
                mosq->protocol = mosq_p_mqtt311;
            }
            else
            {
                return MOSQ_ERR_INVAL;
            }
            break;
        default:
            return MOSQ_ERR_INVAL;
    }
    return MOSQ_ERR_SUCCESS;
}

//----------------------------------------------------------------------------
void mosquitto_connect_callback_set(struct mosquitto *mosq,
                                    void (*on_connect)(struct mosquitto *, void *, int))
{
    pthread_mutex_lock(&mosq->callback_mutex);
    mosq->on_connect = on_connect;
    pthread_mutex_unlock(&mosq->callback_mutex);
}

//----------------------------------------------------------------------------
void mosquitto_disconnect_callback_set(struct mosquitto *mosq,
                                       void (*on_disconnect)(struct mosquitto *, void *, int))
{
    pthread_mutex_lock(&mosq->callback_mutex);
    mosq->on_disconnect = on_disconnect;
    pthread_mutex_unlock(&mosq->callback_mutex);
}

//----------------------------------------------------------------------------
void mosquitto_publish_callback_set(struct mosquitto *mosq,
                                    void (*on_publish)(struct mosquitto *, void *, int))
{
    pthread_mutex_lock(&mosq->callback_mutex);
    mosq->on_publish = on_publish;
    pthread_mutex_unlock(&mosq->callback_mutex);
}

//----------------------------------------------------------------------------
void mosquitto_message_callback_set(struct mosquitto *mosq,
                                    void (*on_message)(struct mosquitto *, void *, const struct mosquitto_message *))
{
    pthread_mutex_lock(&mosq->callback_mutex);
    mosq->on_message = on_message;
    pthread_mutex_unlock(&mosq->callback_mutex);
}

//----------------------------------------------------------------------------
void mosquitto_subscribe_callback_set(struct mosquitto *mosq,
                                      void (*on_subscribe)(struct mosquitto *, void *, int, int, const int *))
{
    pthread_mutex_lock(&mosq->callback_mutex);
    mosq->on_subscribe = on_subscribe;
    pthread_mutex_unlock(&mosq->callback_mutex);
}

//----------------------------------------------------------------------------
void mosquitto_unsubscribe_callback_set(struct mosquitto *mosq,
                                        void (*on_unsubscribe)(struct mosquitto *, void *, int))
{
    pthread_mutex_lock(&mosq->callback_mutex);
    mosq->on_unsubscribe = on_unsubscribe;
    pthread_mutex_unlock(&mosq->callback_mutex);
}

//----------------------------------------------------------------------------
void mosquitto_log_callback_set(struct mosquitto * mosq,
                                void (*on_log)(struct mosquitto *, void *, int, const char *))
{
    pthread_mutex_lock(&mosq->log_callback_mutex);
    mosq->on_log = on_log;
    pthread_mutex_unlock(&mosq->log_callback_mutex);
}

//----------------------------------------------------------------------------
void mosquitto_user_data_set(struct mosquitto *mosq, void *userdata)
{
    if(mosq)
    {
        mosq->userdata = userdata;
    }
}

//----------------------------------------------------------------------------
const char *mosquitto_strerror(int mosq_errno)
{
    switch(mosq_errno)
    {
        case MOSQ_ERR_CONN_PENDING:
            return "Connection pending.";
        case MOSQ_ERR_SUCCESS:
            return "No error.";
        case MOSQ_ERR_NOMEM:
            return "Out of memory.";
        case MOSQ_ERR_PROTOCOL:
            return "A network protocol error occurred when communicating with the broker.";
        case MOSQ_ERR_INVAL:
            return "Invalid function arguments provided.";
        case MOSQ_ERR_NO_CONN:
            return "The client is not currently connected.";
        case MOSQ_ERR_CONN_REFUSED:
            return "The connection was refused.";
        case MOSQ_ERR_NOT_FOUND:
            return "Message not found (internal error).";
        case MOSQ_ERR_CONN_LOST:
            return "The connection was lost.";
        case MOSQ_ERR_TLS:
            return "A TLS error occurred.";
        case MOSQ_ERR_PAYLOAD_SIZE:
            return "Payload too large.";
        case MOSQ_ERR_NOT_SUPPORTED:
            return "This feature is not supported.";
        case MOSQ_ERR_AUTH:
            return "Authorisation failed.";
        case MOSQ_ERR_ACL_DENIED:
            return "Access denied by ACL.";
        case MOSQ_ERR_UNKNOWN:
            return "Unknown error.";
        case MOSQ_ERR_ERRNO:
            return strerror(errno);
        case MOSQ_ERR_EAI:
            return "Lookup error.";
        case MOSQ_ERR_PROXY:
            return "Proxy error.";
        default:
            return "Unknown error.";
    }
}

//----------------------------------------------------------------------------
const char *mosquitto_connack_string(int connack_code)
{
    switch(connack_code)
    {
        case 0:
            return "Connection Accepted.";
        case 1:
            return "Connection Refused: unacceptable protocol version.";
        case 2:
            return "Connection Refused: identifier rejected.";
        case 3:
            return "Connection Refused: broker unavailable.";
        case 4:
            return "Connection Refused: bad user name or password.";
        case 5:
            return "Connection Refused: not authorised.";
        default:
            return "Connection Refused: unknown reason.";
    }
}

//----------------------------------------------------------------------------
int mosquitto_sub_topic_tokenise(const char *subtopic, char ***topics, int *count)
{
    int len;
    int hier_count = 1;
    int start, stop;
    int hier;
    int tlen;
    int i, j;

    if(!subtopic || !topics || !count)
        return MOSQ_ERR_INVAL;

    len = strlen(subtopic);

    for(i=0; i<len; i++)
    {
        if(subtopic[i] == '/')
        {
            if(i > len-1)
            {
                /* Separator at end of line */
            }
            else
            {
                hier_count++;
            }
        }
    }

    (*topics) = mosquitto__calloc(hier_count, sizeof(char *));
    if(!(*topics))
        return MOSQ_ERR_NOMEM;

    start = 0;
    stop = 0;
    hier = 0;

    for(i=0; i<len+1; i++)
    {
        if(subtopic[i] == '/' || subtopic[i] == '\0')
        {
            stop = i;
            if(start != stop)
            {
                tlen = stop-start + 1;
                (*topics)[hier] = mosquitto__calloc(tlen, sizeof(char));
                if(!(*topics)[hier])
                {
                    for(i=0; i<hier_count; i++)
                    {
                        if((*topics)[hier])
                        {
                            mosquitto__free((*topics)[hier]);
                        }
                    }
                    mosquitto__free((*topics));
                    return MOSQ_ERR_NOMEM;
                }
                for(j=start; j<stop; j++)
                {
                    (*topics)[hier][j-start] = subtopic[j];
                }
            }
            start = i+1;
            hier++;
        }
    }

    *count = hier_count;

    return MOSQ_ERR_SUCCESS;
}

//----------------------------------------------------------------------------
int mosquitto_sub_topic_tokens_free(char ***topics, int count)
{
    int i;

    if(!topics || !(*topics) || count<1)
        return MOSQ_ERR_INVAL;

    for(i=0; i<count; i++)
    {
        if((*topics)[i]) mosquitto__free((*topics)[i]);
    }
    mosquitto__free(*topics);

    return MOSQ_ERR_SUCCESS;
}

//----------------------------------------------------------------------------
//----------------------------------------------------------------------------
//----------------------------------------------------------------------------
//----------------------------------------------------------------------------
//----------------------------------------------------------------------------
