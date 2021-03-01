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
#include <stdio.h>
#include <string.h>

#include "mosquitto_emb.h"
#include "logging_mosq.h"
#include "memory_mosq.h"
#include "messages_mosq.h"
#include "mqtt3_protocol.h"
#include "net_mosq.h"
#include "read_handle.h"
#include "send_mosq.h"
#include "util_mosq.h"

//----------------------------------------------------------------------------
int mosquitto__handle_pingreq(struct mosquitto *mosq)
{
    assert(mosq);
    mosquitto__log_printf(mosq, MOSQ_LOG_DEBUG, "Client %s received PINGREQ", mosq->id);
    return mosquitto__send_pingresp(mosq);
}

//----------------------------------------------------------------------------
int mosquitto__handle_pingresp(struct mosquitto *mosq)
{
    assert(mosq);
    mosq->ping_t = 0; /* No longer waiting for a PINGRESP. */
    mosquitto__log_printf(mosq, MOSQ_LOG_DEBUG, "Client %s received PINGRESP", mosq->id);
    return MOSQ_ERR_SUCCESS;
}

//----------------------------------------------------------------------------
int mosquitto__handle_pubackcomp(struct mosquitto *mosq, const char *type)
{
    uint16_t mid;
    int rc;

    assert(mosq);
    rc = mosquitto__read_uint16(&mosq->in_packet, &mid);
    if(rc)
        return rc;
    mosquitto__log_printf(mosq, MOSQ_LOG_DEBUG, "Client %s received %s (Mid: %d)", mosq->id, type, mid);

    if(!mosquitto__message_delete(mosq, mid, mosq_md_out))
    {
        /* Only inform the client the message has been sent once. */
        pthread_mutex_lock(&mosq->callback_mutex);
        if(mosq->on_publish)
        {
            mosq->in_callback = true;
            mosq->on_publish(mosq, mosq->userdata, mid);
            mosq->in_callback = false;
        }
        pthread_mutex_unlock(&mosq->callback_mutex);
    }

    return MOSQ_ERR_SUCCESS;
}

//----------------------------------------------------------------------------
int mosquitto__handle_pubrec(struct mosquitto *mosq)
{
    uint16_t mid;
    int rc;

    assert(mosq);
    rc = mosquitto__read_uint16(&mosq->in_packet, &mid);
    if(rc)
        return rc;
    mosquitto__log_printf(mosq, MOSQ_LOG_DEBUG, "Client %s received PUBREC (Mid: %d)", mosq->id, mid);

    rc = mosquitto__message_out_update(mosq, mid, mosq_ms_wait_for_pubcomp);

    if(rc)
        return rc;
    rc = mosquitto__send_pubrel(mosq, mid);
    if(rc)
        return rc;

    return MOSQ_ERR_SUCCESS;
}

//----------------------------------------------------------------------------
int mosquitto__handle_pubrel(struct mosquitto *mosq)
{
    uint16_t mid;
    struct mosquitto_message_all * message = NULL;
    int rc;

    assert(mosq);
    if(mosq->protocol == mosq_p_mqtt311)
    {
        if((mosq->in_packet.command&0x0F) != 0x02)
        {
            return MOSQ_ERR_PROTOCOL;
        }
    }
    rc = mosquitto__read_uint16(&mosq->in_packet, &mid);
    if(rc)
        return rc;
    mosquitto__log_printf(mosq, MOSQ_LOG_DEBUG, "Client %s received PUBREL (Mid: %d)", mosq->id, mid);

    if(!mosquitto__message_remove(mosq, mid, mosq_md_in, &message))
    {
        /* Only pass the message on if we have removed it from the queue - this
         * prevents multiple callbacks for the same message. */
        pthread_mutex_lock(&mosq->callback_mutex);
        if(mosq->on_message)
        {
            mosq->in_callback = true;
            mosq->on_message(mosq, mosq->userdata, &message->msg);
            mosq->in_callback = false;
        }
        pthread_mutex_unlock(&mosq->callback_mutex);
        mosquitto__message_cleanup(&message);
    }

    rc = mosquitto__send_pubcomp(mosq, mid);
    if(rc)
        return rc;

    return MOSQ_ERR_SUCCESS;
}

//----------------------------------------------------------------------------
int mosquitto__handle_suback(struct mosquitto *mosq)
{
    uint16_t mid;
    uint8_t qos;
    int *granted_qos;
    int qos_count;
    int i = 0;
    int rc;

    assert(mosq);

    mosquitto__log_printf(mosq, MOSQ_LOG_DEBUG, "Client %s received SUBACK", mosq->id);
    rc = mosquitto__read_uint16(&mosq->in_packet, &mid);
    if(rc)
        return rc;

    qos_count = mosq->in_packet.remaining_length - mosq->in_packet.pos;
    granted_qos = mosquitto__malloc(qos_count*sizeof(int));
    if(!granted_qos)
        return MOSQ_ERR_NOMEM;
//u_printf("==Z0\n");
    while(mosq->in_packet.pos < mosq->in_packet.remaining_length)
    {
        rc = mosquitto__read_byte(&mosq->in_packet, &qos);
        if(rc)
        {
            mosquitto__free(granted_qos);
            return rc;
        }
        granted_qos[i] = (int)qos;
        i++;
    }
    mosquitto__free(granted_qos);
//u_printf("==Z1\n");

    return MOSQ_ERR_SUCCESS;
}

//----------------------------------------------------------------------------
int mosquitto__handle_unsuback(struct mosquitto *mosq)
{
    uint16_t mid;
    int rc;

    assert(mosq);
    mosquitto__log_printf(mosq, MOSQ_LOG_DEBUG, "Client %s received UNSUBACK", mosq->id);
    rc = mosquitto__read_uint16(&mosq->in_packet, &mid);
    if(rc)
        return rc;

    pthread_mutex_lock(&mosq->callback_mutex);
    if(mosq->on_unsubscribe)
    {
        mosq->in_callback = true;
        mosq->on_unsubscribe(mosq, mosq->userdata, mid);
        mosq->in_callback = false;
    }
    pthread_mutex_unlock(&mosq->callback_mutex);


    return MOSQ_ERR_SUCCESS;
}

//----------------------------------------------------------------------------
//----------------------------------------------------------------------------
//----------------------------------------------------------------------------
//----------------------------------------------------------------------------
//----------------------------------------------------------------------------
