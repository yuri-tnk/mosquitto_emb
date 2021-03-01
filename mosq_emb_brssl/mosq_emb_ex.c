/*

Copyright © 2021 Yuri Tiomkin
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
 * Copyright (c) 2017 Thomas Pornin <pornin@bolet.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>

#include "mosquitto_internal.h"
#include "net_mosq.h"
#include "mqtt3_protocol.h"
#include "memory_mosq.h"
#include "mosquitto_emb.h"
#include "read_handle.h"

#define COMPAT_EINTR  EINTR

#define TX_DRV_EXIT   102
#define FULL_PKT_RX   1002

static int pkt_rx_drv(struct mosquitto * mosq,
                      unsigned char * rd_buf,        // input data
                      int nb,                        // input data len
                      int * n_to_read,               // [OUT] for next read(if any)
                      unsigned char ** buf_to_read); // [OUT] for next read(if any)
static int tx_drv(struct mosquitto * mosq,
                  int max_len,             // ssl_buf max_len, no SSL- (-1)
                  unsigned char * ssl_buf, // no SSL - NULL
                  int * was_wr);           // [OUT]
static int do_processing_mqtt_packet(struct mosquitto * mosq);


//----------------------------------------------------------------------------
int mosquitto_set_brssl_param(struct mosquitto * mosq,
                              char * ca_name,
	                          char * cert_name,
	                          char * key_name,
                              char * sni,
                              int verbose) 
{
    int rc = 0;
    if(mosq == NULL)
    {
        rc = MOSQ_ERR_INVAL; 
    }
    else
    {
        mosq->ssl_cafile       = ca_name;
        mosq->ssl_cli_certfile = cert_name;
        mosq->ssl_cli_keyfile  = key_name;
        mosq->ssl_sni          = sni;
        if(mosq->srv_full_name != NULL)
        {
            mosquitto__free(mosq->srv_full_name);
            mosq->srv_full_name = NULL;
        }
        mosq->verbose = verbose;
    }
    return rc;
}

// YVT
//----------------------------------------------------------------------------
int mosquitto__signal_eventfd(mosq_eventfd_t efd)
{
    uint64_t val = 1LU;
    int rv;
    int rc = MOSQ_ERR_ERRNO;

    rv = (int)write(efd, &val, sizeof(uint64_t));
    if(rv == sizeof(uint64_t))
    {
        rc = MOSQ_ERR_SUCCESS;
    }
    else
    {
        //u_printf("Set event - Err, %d \n", (int)val); fflush(stdout);
    }
    return rc;
}

//----------------------------------------------------------------------------
int mosquitto__clear_eventfd(mosq_eventfd_t efd)
{
    uint64_t val = 0LU;
    int rv;
    int rc = MOSQ_ERR_ERRNO;

    rv = (int)read(efd, &val, sizeof(uint64_t));
    if(rv == sizeof(uint64_t))
    {
        rc = MOSQ_ERR_SUCCESS;
    }
    else
    {
        // u_printf("Clear event - Err, %d \n", (int)rv); fflush(stdout);
        //  break;
    }

    return rc;
}

//----------------------------------------------------------------------------
int mosquitto__create_eventfd(mosq_eventfd_t * efd_val)
{
    int efd;
    int rc = MOSQ_ERR_ERRNO;

    if(efd_val == NULL)
    {
        rc = MOSQ_ERR_INVAL;
    }
    else
    {
        efd = eventfd(0, // Init Value
                      EFD_NONBLOCK);
        if(efd == -1)
        {
            rc = MOSQ_ERR_ERRNO;
        }
        else
        {
            *efd_val = efd;
            rc = MOSQ_ERR_SUCCESS;
        }
    }

    return rc;
}

//----------------------------------------------------------------------------
void print_ssl_connection_details(br_ssl_engine_context * cc)
{
    char csn[80];
    const char *pname;

    u_printf( "Handshake completed\n");
    u_printf( "   version:               ");
    switch (cc->session.version)
    {
        case BR_SSL30:
            u_printf( "SSL 3.0");
            break;
        case BR_TLS10:
            u_printf( "TLS 1.0");
            break;
        case BR_TLS11:
            u_printf( "TLS 1.1");
            break;
        case BR_TLS12:
            u_printf( "TLS 1.2");
            break;
        default:
            u_printf( "unknown (0x%04X)",
                    (unsigned)cc->session.version);
            break;
    }
    u_printf( "\n");
    get_suite_name_ext(cc->session.cipher_suite, csn, sizeof csn);
    u_printf( "   cipher suite:          %s\n", csn);
    if (uses_ecdhe(cc->session.cipher_suite))
    {
        get_curve_name_ext(br_ssl_engine_get_ecdhe_curve(cc),
                           csn, sizeof csn);
        u_printf( "   ECDHE curve:           %s\n", csn);
    }
    u_printf( "   secure renegotiation:  %s\n",
            cc->reneg == 1 ? "no" : "yes");
    pname = br_ssl_engine_get_selected_protocol(cc);
    if (pname != NULL)
    {
        u_printf( "   protocol name (ALPN):  %s\n", pname);
    }
}

//----------------------------------------------------------------------------
int ssl_closed_details(br_ssl_engine_context * cc)
{
    int err;
    int rc = 0;

    err = br_ssl_engine_last_error(cc);
    if (err == BR_ERR_OK)
    {
        //if (verbose)
        {
            u_printf( "SSL closed normally\n");
        }
        rc = 0;
    }
    else
    {
        u_printf( "ERROR: SSL error %d", err);
        rc = MOSQ_ERR_TLS;
        if (err >= BR_ERR_SEND_FATAL_ALERT)
        {
            err -= BR_ERR_SEND_FATAL_ALERT;
            u_printf( " (sent alert %d)\n", err);
        }
        else if (err >= BR_ERR_RECV_FATAL_ALERT)
        {
            err -= BR_ERR_RECV_FATAL_ALERT;
            u_printf( " (received alert %d)\n", err);
        }
        else
        {
            const char *ename;

            ename = find_error_name(err, NULL);
            if (ename == NULL)
            {
                ename = "unknown";
            }
            u_printf( " (%s)\n", ename);
        }
    }
    return rc;
}

//----------------------------------------------------------------------------
int check_socket_rd_err(int read_length)
{
    int rc = MOSQ_ERR_SUCCESS;

    if(read_length == 0)
    {
        rc = MOSQ_ERR_CONN_LOST; /* EOF */
    }
    else if(errno == EAGAIN || errno == COMPAT_EWOULDBLOCK)
    {
        rc = MOSQ_ERR_SUCCESS;
    }
    else
    {
        switch(errno)
        {
            case COMPAT_ECONNRESET:
                rc = MOSQ_ERR_CONN_LOST;
                break;
            case COMPAT_EINTR:
                rc = MOSQ_ERR_SUCCESS;
                break;
            default:
                rc = MOSQ_ERR_ERRNO;
                break;
        }
    }
    return rc;
}

//----------------------------------------------------------------------------
int check_socket_wr_err(void)
{
    int rc = MOSQ_ERR_SUCCESS;

    if(errno == EAGAIN || errno == COMPAT_EWOULDBLOCK)
    {
        rc = MOSQ_ERR_SUCCESS;
    }
    else
    {
        switch(errno)
        {
            case COMPAT_ECONNRESET:
                rc = MOSQ_ERR_CONN_LOST;
                break;
            default:
                rc = MOSQ_ERR_ERRNO;
                break;
        }
    }
    return rc;
}

//----------------------------------------------------------------------------
int do_processing_mqtt_packet(struct mosquitto * mosq)
{
    int rc;

    mosq->in_packet.pos = 0;

    rc = mosquitto__packet_handle(mosq);

    /* Free data and reset values */
    mosquitto__packet_cleanup(&mosq->in_packet);

    pthread_mutex_lock(&mosq->msgtime_mutex);
    mosq->last_msg_in = mosquitto_time();
    pthread_mutex_unlock(&mosq->msgtime_mutex);

    return rc;
}

//----------------------------------------------------------------------------
int mosquitto__loop_rc_handle(struct mosquitto * mosq, int rc)
{
    if(rc != 0)
    {
        mosquitto__socket_close(mosq);

        pthread_mutex_lock(&mosq->state_mutex);
        if(mosq->state == mosq_cs_disconnecting || mosq->state == mosq_cs_disconnected)
        {
            rc = MOSQ_ERR_SUCCESS;
        }
        pthread_mutex_unlock(&mosq->state_mutex);

        pthread_mutex_lock(&mosq->callback_mutex);
        if(mosq->on_disconnect)
        {
            mosq->in_callback = true;
            mosq->on_disconnect(mosq, mosq->userdata, rc);
            mosq->in_callback = false;
        }
        pthread_mutex_unlock(&mosq->callback_mutex);

        return rc;
    }
    return rc;
}

//----------------------------------------------------------------------------
void tx_update_packet_queue(struct mosquitto * mosq)
{
    pthread_mutex_lock(&mosq->current_out_packet_mutex);
    pthread_mutex_lock(&mosq->out_packet_mutex);

    mosq->current_out_packet = mosq->out_packet;
    if(mosq->out_packet != NULL)
    {
        mosq->out_packet = mosq->out_packet->next;
        if(mosq->out_packet == NULL)
        {
            mosq->out_packet_last = NULL;
        }
    }
    pthread_mutex_unlock(&mosq->out_packet_mutex);
    pthread_mutex_unlock(&mosq->current_out_packet_mutex);
}

//----------------------------------------------------------------------------
void tx_update_packet_queue_1(struct mosquitto * mosq)
{
    pthread_mutex_lock(&mosq->current_out_packet_mutex);
    pthread_mutex_lock(&mosq->out_packet_mutex);
    if(mosq->out_packet != NULL && mosq->current_out_packet == NULL)
    {
        mosq->current_out_packet = mosq->out_packet;

        mosq->out_packet = mosq->out_packet->next;
        if(mosq->out_packet == NULL)
        {
            mosq->out_packet_last = NULL;
        }
    }
    pthread_mutex_unlock(&mosq->out_packet_mutex);
    pthread_mutex_unlock(&mosq->current_out_packet_mutex);
}

//----------------------------------------------------------------------------
// mosquitto_loop() replacement
//----------------------------------------------------------------------------
int do_rx_tx(struct mosquitto * mosq, int timeout)
{
    unsigned char * ssl_buf;
    size_t len;
    time_t now;
    unsigned int st;
    int rc;
    int nb;
    int timeout_ms;
    int was_wr = 0;
    unsigned char sbuf[8];
    struct pollfd pfd[2];
    br_ssl_engine_context * cc = NULL;

    if(mosq == NULL)
    {
        return MOSQ_ERR_INVAL;
    }

    if(mosq->ssl != NULL)
    {
        cc = &mosq->ssl->cc.eng;
    }

    memset(pfd, 0, sizeof(pfd));

    pfd[0].fd = mosq->sock;
    pfd[1].fd = mosq->efd;

    if(mosq->ssl == NULL) // No SSL
    {
        pfd[0].events |= POLLIN; // Rx from socket

        pthread_mutex_lock(&mosq->current_out_packet_mutex);
        pthread_mutex_lock(&mosq->out_packet_mutex);
        if(mosq->out_packet != NULL || mosq->current_out_packet != NULL)
        {
            pfd[0].events |= POLLOUT;
        }
        pthread_mutex_unlock(&mosq->out_packet_mutex);
        pthread_mutex_unlock(&mosq->current_out_packet_mutex);

        pfd[1].events |= POLLIN; // to process signal "Mosquitto has a packet(s) to send"
    }
    else // SSL
    {
        st = br_ssl_engine_current_state(cc);
        if(st == BR_SSL_CLOSED)
        {
            goto ssl_closed_exit;
        }

        if(st & BR_SSL_SENDREC) // record data is ready to be sent to the peer
        {
            pfd[0].events |= POLLOUT;
        }

        if(st & BR_SSL_RECVREC) // engine may receive records from the peer
        {
            pfd[0].events |= POLLIN;
        }

        if(st & BR_SSL_SENDAPP) // User may send - engine may accept application data to send
        {
            pthread_mutex_lock(&mosq->current_out_packet_mutex);
            pthread_mutex_lock(&mosq->out_packet_mutex);

            if(mosq->out_packet != NULL || mosq->current_out_packet != NULL)
            {
               // If output queue has a packet(s) -
               // it will be processed in poll()

                pfd[0].events |= POLLOUT;
            }
            pthread_mutex_unlock(&mosq->out_packet_mutex);
            pthread_mutex_unlock(&mosq->current_out_packet_mutex);

            pfd[1].events |= POLLIN; // to process signal "Mosquitto has a packet(s) to send"
        }

        // 'User may receive' - we do not check the condition in poll()
        // Instead, we check the condition at sendrec_ok, recvrec_ok, sendapp_ok
        // | recvrec | --> | processing inside SSL engine | --> | recvapp(maybe)|
    }

    timeout_ms = timeout;
    if(timeout_ms < 0)
    {
        timeout_ms = 1000;
    }

    now = mosquitto_time();
    if(mosq->next_msg_out != 0 && ((now + timeout_ms/1000) > mosq->next_msg_out))
    {
        timeout_ms = ((int)mosq->next_msg_out - (int)now)*1000;
    }

    if(timeout_ms < 0)
    {
        /* There has been a delay somewhere which means we should have already
         * sent a message. */
        timeout_ms = 0;
    }

    nb = poll(pfd, 2, timeout_ms);
    if(nb < 0)
    {
        //u_printf("Poll() error\n");
        if(errno == EINTR)
        {
            rc = MOSQ_ERR_SUCCESS;
        }
        else
        {
            rc = MOSQ_ERR_ERRNO;
        }
    }
    else if(nb == 0)
    {
        //u_printf("Poll() timeout\n");
        rc = MOSQ_ERR_SUCCESS;
    }
    else
    {
        if(pfd[0].revents & POLLIN) // ready Rx from socket
        {
            if(mosq->ssl != NULL) // SSL receiving =============
            {
                rc = MOSQ_ERR_SUCCESS;

                st = br_ssl_engine_current_state(cc);
                if(st == BR_SSL_CLOSED)
                {
                    goto ssl_closed_exit;
                }

                if(st & BR_SSL_RECVREC)
                {
                    ssl_buf = br_ssl_engine_recvrec_buf(cc, &len);

                    nb = read(mosq->sock, ssl_buf, len);
                    if(nb <= 0)
                    {
                        rc = check_socket_rd_err(nb);
                        if(rc != MOSQ_ERR_SUCCESS)
                        {
                            return rc;
                        }
                    }
                    else
                    {
                        br_ssl_engine_recvrec_ack(cc, nb);
                    }
                }

                st = br_ssl_engine_current_state(cc);
                if(st == BR_SSL_CLOSED)
                {
                    goto ssl_closed_exit;
                }

                if(st & BR_SSL_RECVAPP)
                {
                    if(mosq->hsdetails == 0)
                    {
                        mosq->hsdetails = 1; // Do it once

                        print_ssl_connection_details(cc); // SSL was connected
                    }

                    ssl_buf = br_ssl_engine_recvapp_buf(cc, &len);
                    // Accumulate user data from SSL engine inside a 'iov buffer'
                    rc = write_v(&mosq->vlist, ssl_buf, len);
                    if(rc != len)
                    {
                        return MOSQ_ERR_NOMEM;
                    }

                    br_ssl_engine_recvapp_ack(cc, rc);

                    if(mosq->in_packet.command == 0)
                    {
                        mosq->rx_drv_state = 0;

                        mosq->n_to_read = 1;
                        mosq->buf_to_read = sbuf;
                    }

                    for(;;)
                    {
                        // Read user data from 'iov buffer'
                        nb = read_v(&mosq->vlist, mosq->buf_to_read, mosq->n_to_read);
                        if(nb > 0)
                        {
                            //u_printf("read_v %d\n", nb);
                            rc = pkt_rx_drv(mosq,
                                            mosq->buf_to_read,
                                            nb,
                                            &mosq->n_to_read,
                                            &mosq->buf_to_read); // fo next reading (if any)
                            if(rc == FULL_PKT_RX)
                            {
                                //u_printf("Got packet\n");
                                rc = do_processing_mqtt_packet(mosq);

                                break;
                            }
                            else
                            {
                                if(rc != MOSQ_ERR_SUCCESS)
                                {
                                    break;
                                }
                            }
                        }
                        else // no more data to read
                        {
                            rc = MOSQ_ERR_SUCCESS;
                            errno = EAGAIN;
                            break;
                        }
                    }

                    if(rc != MOSQ_ERR_SUCCESS)// || errno == EAGAIN || errno == COMPAT_EWOULDBLOCK)
                    {
                        return mosquitto__loop_rc_handle(mosq, rc);
                    }

                }
            }
            else // No SSL
            {
                if(mosq->in_packet.command == 0)
                {
                    mosq->rx_drv_state = 0;

                    mosq->n_to_read = 1;
                    mosq->buf_to_read = sbuf;
                }

                for(;;)
                {
                    nb = read(mosq->sock, mosq->buf_to_read, mosq->n_to_read);
                    if(nb > 0)
                    {
                        rc = pkt_rx_drv(mosq,
                                        mosq->buf_to_read,
                                        nb,
                                        &mosq->n_to_read,
                                        &mosq->buf_to_read); // for next readinf(if any)
                        if(rc == FULL_PKT_RX)
                        {
                            rc = do_processing_mqtt_packet(mosq);
                            break;
                        }
                        else
                        {
                            if(rc != MOSQ_ERR_SUCCESS)
                            {
                                break;
                            }
                        }
                    }
                    else // socket error
                    {
                        rc = check_socket_rd_err(nb);
                        if(rc != MOSQ_ERR_SUCCESS)
                        {
                            return rc;
                        }

                        break;
                    }
                }

                if(rc != MOSQ_ERR_SUCCESS) // || errno == EAGAIN || errno == COMPAT_EWOULDBLOCK)
                {
                    return mosquitto__loop_rc_handle(mosq, rc);
                }
            }
        }

//========= sending =============

        if(pfd[1].revents & POLLIN)
        {
            mosquitto__clear_eventfd(mosq->efd);

            if(mosq->sock != INVALID_SOCKET)
            {
                pfd[0].revents |= POLLOUT;
            }
        }

        if(pfd[0].revents & POLLOUT)
        {
            if(mosq->ssl == NULL)
            {
                rc = tx_drv(mosq,
                            -1,       // len in not SSL mode - not uses
                            NULL,     // not SSL - NULL
                            &was_wr); // [OUT]
                //u_printf("Tx wr: %d rc: %d\n", was_wr, rc);

                if(rc != MOSQ_ERR_SUCCESS) // || errno == EAGAIN || errno == COMPAT_EWOULDBLOCK)
                {
                    return mosquitto__loop_rc_handle(mosq, rc);
                }
            }
            else
            {
                rc = MOSQ_ERR_SUCCESS;

                st = br_ssl_engine_current_state(cc);
                if(st == BR_SSL_CLOSED)
                {
                    goto ssl_closed_exit;
                }

                if(st & BR_SSL_SENDREC) // record data is ready to be sent to the peer
                {
                    ssl_buf = br_ssl_engine_sendrec_buf(cc, &len);

                    nb = write(mosq->sock, ssl_buf, len);
                    if(nb <= 0)
                    {
                        rc = check_socket_wr_err();
                    }
                    else
                    {
                        br_ssl_engine_sendrec_ack(cc, nb);
                    }
                }

                if(rc == MOSQ_ERR_SUCCESS)
                {
                    st = br_ssl_engine_current_state(cc);
                    if(st == BR_SSL_CLOSED)
                    {
                        goto ssl_closed_exit;
                    }

                    if(st & BR_SSL_SENDAPP) // User may send - engine may accept application data to send
                    {
                        if(mosq->hsdetails == 0)
                        {
                            mosq->hsdetails = 1; // Do it once
                            print_ssl_connection_details(cc); // SSL was connected
                        }

                        ssl_buf = br_ssl_engine_sendapp_buf(cc, &len);

                        // Now - wr to 'ssl_buf'
                        rc = tx_drv(mosq,
                                    len,
                                    ssl_buf, // no SSL - NULL
                                    &was_wr); // [OUT]
                        //u_printf("ssl: tx_drv was_wr: %d rc: %d\n", was_wr, rc);
                        if(was_wr > 0)
                        {
                            br_ssl_engine_sendapp_ack(cc, was_wr);
                            br_ssl_engine_flush(cc, 0);  // Force SSL engine processing
                        }

                        if(rc != MOSQ_ERR_SUCCESS) // || errno == EAGAIN || errno == COMPAT_EWOULDBLOCK)
                        {
                            return mosquitto__loop_rc_handle(mosq, rc);
                        }
                    }
                }
            }
        }
    }

    if(rc == MOSQ_ERR_SUCCESS)
    {
        rc = mosquitto_loop_misc(mosq);
    }
    return rc;

ssl_closed_exit:
    u_printf ("engine closed. sock: %d\n", mosq->sock);
    // ToDo - release SSL resources (memory etc.)
    // ToDo - close mosq sock
    rc = ssl_closed_details(cc);
    exit(0); // Remove in embedded app

    return rc;
}

//----------------------------------------------------------------------------
int pkt_rx_drv(struct mosquitto * mosq,
               unsigned char * rd_buf,       // input data
               int nb,                       // input data len
               int * n_to_read,              // for next read(if any)
               unsigned char ** buf_to_read) // for next read(if any)
{
    int rc = MOSQ_ERR_SUCCESS;
    int val;

    if(mosq->rx_drv_state == 0) // cmd - 1byte
    {
        mosq->in_packet.command = rd_buf[0];

        *buf_to_read = rd_buf;
        *n_to_read = 1;

        mosq->rx_drv_state = 1;
    }
    else if(mosq->rx_drv_state == 1) // len(1..4 bytes)
    {
        if(mosq->in_packet.remaining_count <= 0)
        {
            val = rd_buf[0];

            mosq->in_packet.remaining_count--;
            /* Max 4 bytes length for remaining length as defined by protocol.
             * Anything more likely means a broken/malicious peer.
             */
            if(mosq->in_packet.remaining_count < -4)
            {
                return MOSQ_ERR_PROTOCOL;
            }

            mosq->in_packet.remaining_length += (val & 127) * mosq->in_packet.remaining_mult;
            mosq->in_packet.remaining_mult   *= 128;

            if((val & 128) == 0)
            {
                /* We have finished reading remaining_length, so make remaining_count
                 * positive. */
                mosq->in_packet.remaining_count = (int8_t)(mosq->in_packet.remaining_count * (-1));

                // FIXME - client case for incoming message received from broker too large
                if(mosq->in_packet.remaining_length > 0)
                {
                    mosq->in_packet.payload = mosquitto__malloc(mosq->in_packet.remaining_length * sizeof(uint8_t));
                    if(mosq->in_packet.payload == NULL)
                    {
                        return MOSQ_ERR_NOMEM;
                    }
                    mosq->in_packet.to_process = mosq->in_packet.remaining_length;
                    mosq->in_packet.pos = 0;

                    *buf_to_read = &mosq->in_packet.payload[mosq->in_packet.pos];
                    *n_to_read   = mosq->in_packet.to_process;

                    mosq->rx_drv_state = 2;
                }
                else // PINGRESP, for instance
                {
                    rc = FULL_PKT_RX;       // Ok, finished
                    mosq->rx_drv_state = 0;
                }
            }
            else // still stage 1
            {
                *buf_to_read = rd_buf;
                *n_to_read   = 1;
            }
        }
    }
    else if(mosq->rx_drv_state == 2)
    {
        if(nb > 0)
        {
            mosq->in_packet.to_process -= (uint32_t)nb;
            mosq->in_packet.pos        += (uint32_t)nb;

            if(mosq->in_packet.to_process <= 0)
            {
                // Ok, finished
                rc = FULL_PKT_RX;
                mosq->rx_drv_state = 0;
            }
            else
            {
                *buf_to_read = &mosq->in_packet.payload[mosq->in_packet.pos];
                *n_to_read   = mosq->in_packet.to_process;
            }
        }
        else // Internal Err
        {
            rc = MOSQ_ERR_ERRNO;
        }
    }

    return rc;
}

//----------------------------------------------------------------------------
int tx_drv(struct mosquitto * mosq,
           int max_len,             // ssl_buf max_len, no SSL- (-1)
           unsigned char * ssl_buf, // no SSL - NULL
           int * was_wr)            // [OUT]
{
    struct mosquitto__packet * packet = NULL;
    int nb;
    int rc = MOSQ_ERR_SUCCESS;

    if(mosq == NULL || was_wr == NULL)
        return MOSQ_ERR_INVAL;
    if(mosq->sock == INVALID_SOCKET)
        return MOSQ_ERR_NO_CONN;

    *was_wr = 0;

    if(mosq->tx_drv_state == 0)
    {
        // Update TX queue header
        for(;;)
        {
            tx_update_packet_queue_1(mosq);

            pthread_mutex_lock(&mosq->current_out_packet_mutex);
            packet = mosq->current_out_packet;
            pthread_mutex_unlock(&mosq->current_out_packet_mutex);

            if(packet == NULL)
            {
                // Nothing to send - exit drv

                mosq->tx_drv_state = 0;
                break;
            }
            else
            {
                if(packet->to_process > 0)
                {
                    mosq->tx_drv_state = 2;  // Do send
                    break;
                }
                else  // Nothing to send in the current packet - try next
                {
                    // just to force the updating in the function
                    // tx_update_packet_queue_1()
                    pthread_mutex_lock(&mosq->current_out_packet_mutex);
                    mosq->current_out_packet = NULL;
                    pthread_mutex_unlock(&mosq->current_out_packet_mutex);
                }
            }
        }
    }

    if(mosq->tx_drv_state == 2) // Do sending packet content
    {
        // 'packet' was obtained in stage 0

        //pthread_mutex_lock(&mosq->current_out_packet_mutex);
        //packet = mosq->current_out_packet;
        //pthread_mutex_unlock(&mosq->current_out_packet_mutex);

        if(packet != NULL && packet->to_process > 0)
        {
            if(mosq->ssl)  // Wr to SSL provided buffer
            {
                if(packet->to_process > max_len)
                    nb = max_len;
                else
                    nb = packet->to_process;
                //--- wr to SSL engine
                memcpy(ssl_buf,
                       &(packet->payload[packet->pos]),
                       nb);

                packet->to_process -= nb;
                packet->pos        += nb;

                if(packet->to_process == 0)
                {
                    mosq->tx_drv_state = 3; // Finished_send_packet
                }

                *was_wr = nb;
            }
            else // no SSL - wr to socket directly
            {
                nb = write(mosq->sock,
                           &(packet->payload[packet->pos]),
                           packet->to_process);
                //u_printf("wr to socket: %d\n", nb);
                if(nb > 0)
                {
                    packet->to_process -= nb;
                    packet->pos        += nb;

                    if(packet->to_process == 0)
                    {
                        mosq->tx_drv_state = 3; // Finished_send_packet
                    }
                    *was_wr = nb;
                }
                else
                {
                    rc = check_socket_wr_err();
                    mosq->tx_drv_state = 0; //Exit
                }
            }
        }
        else // Internal Err
        {
            mosq->tx_drv_state = 0; //TX_DRV_EXIT;
            rc = MOSQ_ERR_ERRNO;
        }
    }

    if(mosq->tx_drv_state == 3) // After packet sending
    {
        // 'packet' was obtained in stage 0

        // pthread_mutex_lock(&mosq->current_out_packet_mutex);
        // packet = mosq->current_out_packet;
        // pthread_mutex_unlock(&mosq->current_out_packet_mutex);

        if(((packet->command) & 0xF6) == PUBLISH)
        {
            pthread_mutex_lock(&mosq->callback_mutex);
            if(mosq->on_publish)
            {
                /* This is a QoS=0 message */
                mosq->in_callback = true;
                mosq->on_publish(mosq, mosq->userdata, packet->mid);
                mosq->in_callback = false;
            }
            pthread_mutex_unlock(&mosq->callback_mutex);
        }
        else if(((packet->command) & 0xF0) == DISCONNECT)
        {
            /* FIXME what cleanup needs doing here?
             * incoming/outgoing messages? */

            mosquitto__socket_close(mosq);

            /* Start of duplicate, possibly unnecessary code.
             * This does leave things in a consistent state at least. */
            /* Free data and reset values */

            tx_update_packet_queue(mosq);

            mosquitto__packet_cleanup(packet);
            mosquitto__free(packet);

            pthread_mutex_lock(&mosq->msgtime_mutex);
            mosq->next_msg_out = mosquitto_time() + mosq->keepalive;
            pthread_mutex_unlock(&mosq->msgtime_mutex);

            /* End of duplicate, possibly unnecessary code */

            pthread_mutex_lock(&mosq->callback_mutex);
            if(mosq->on_disconnect)
            {
                mosq->in_callback = true;
                mosq->on_disconnect(mosq, mosq->userdata, 0);
                mosq->in_callback = false;
            }
            pthread_mutex_unlock(&mosq->callback_mutex);

            rc = MOSQ_ERR_SUCCESS;
            mosq->tx_drv_state = 0;  // exit

            // return rc;
        }

        if(mosq->tx_drv_state != 0) // Final
        {
            tx_update_packet_queue(mosq);

            mosquitto__packet_cleanup(packet);
            mosquitto__free(packet);

            pthread_mutex_lock(&mosq->msgtime_mutex);
            mosq->next_msg_out = mosquitto_time() + mosq->keepalive;
            pthread_mutex_unlock(&mosq->msgtime_mutex);

            mosq->tx_drv_state = 0;
        }
    }

    return rc;
}


//----------------------------------------------------------------------------
//----------------------------------------------------------------------------
//----------------------------------------------------------------------------
//----------------------------------------------------------------------------
//----------------------------------------------------------------------------
