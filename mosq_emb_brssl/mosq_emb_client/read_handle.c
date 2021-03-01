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
#include "time_mosq.h"
#include "util_mosq.h"

int mosquitto__packet_handle(struct mosquitto *mosq)
{
	assert(mosq);

	switch((mosq->in_packet.command)&0xF0)
    {
		case PINGREQ:
			return mosquitto__handle_pingreq(mosq);
		case PINGRESP:
			return mosquitto__handle_pingresp(mosq);
		case PUBACK:
			return mosquitto__handle_pubackcomp(mosq, "PUBACK");
		case PUBCOMP:
			return mosquitto__handle_pubackcomp(mosq, "PUBCOMP");
		case PUBLISH:
			return mosquitto__handle_publish(mosq);
		case PUBREC:
			return mosquitto__handle_pubrec(mosq);
		case PUBREL:
			return mosquitto__handle_pubrel(mosq);
		case CONNACK:
			return mosquitto__handle_connack(mosq);
		case SUBACK:
			return mosquitto__handle_suback(mosq);
		case UNSUBACK:
			return mosquitto__handle_unsuback(mosq);
		default:
			/* If we don't recognise the command, return an error straight away. */
			mosquitto__log_printf(mosq, MOSQ_LOG_ERR, "Error: Unrecognised command %d\n", (mosq->in_packet.command)&0xF0);
			return MOSQ_ERR_PROTOCOL;
	}
}

int mosquitto__handle_publish(struct mosquitto *mosq)
{
	uint8_t header;
	struct mosquitto_message_all *message;
	int rc = 0;
	uint16_t mid;

	assert(mosq);

	message = mosquitto__calloc(1, sizeof(struct mosquitto_message_all));
	if(!message) return MOSQ_ERR_NOMEM;

	header = mosq->in_packet.command;

	message->dup = (header & 0x08)>>3;
	message->msg.qos = (header & 0x06)>>1;
	message->msg.retain = (header & 0x01);

	rc = mosquitto__read_string(&mosq->in_packet, &message->msg.topic);
	if(rc){
		mosquitto__message_cleanup(&message);
		return rc;
	}
	if(!strlen(message->msg.topic)){
		mosquitto__message_cleanup(&message);
		return MOSQ_ERR_PROTOCOL;
	}

	if(message->msg.qos > 0){
		rc = mosquitto__read_uint16(&mosq->in_packet, &mid);
		if(rc){
			mosquitto__message_cleanup(&message);
			return rc;
		}
		message->msg.mid = (int)mid;
	}

	message->msg.payloadlen = mosq->in_packet.remaining_length - mosq->in_packet.pos;
	if(message->msg.payloadlen){
		message->msg.payload = mosquitto__calloc(message->msg.payloadlen+1, sizeof(uint8_t));
		if(!message->msg.payload){
			mosquitto__message_cleanup(&message);
			return MOSQ_ERR_NOMEM;
		}
		rc = mosquitto__read_bytes(&mosq->in_packet, message->msg.payload, message->msg.payloadlen);
		if(rc){
			mosquitto__message_cleanup(&message);
			return rc;
		}
	}
	mosquitto__log_printf(mosq, MOSQ_LOG_DEBUG,
			"Client %s received PUBLISH (d%d, q%d, r%d, m%d, '%s', ... (%ld bytes))",
			mosq->id, message->dup, message->msg.qos, message->msg.retain,
			message->msg.mid, message->msg.topic,
			(long)message->msg.payloadlen);

	message->timestamp = mosquitto_time();
	switch(message->msg.qos){
		case 0:
			pthread_mutex_lock(&mosq->callback_mutex);
			if(mosq->on_message){
				mosq->in_callback = true;
				mosq->on_message(mosq, mosq->userdata, &message->msg);
				mosq->in_callback = false;
			}
			pthread_mutex_unlock(&mosq->callback_mutex);
			mosquitto__message_cleanup(&message);
			return MOSQ_ERR_SUCCESS;
		case 1:
			rc = mosquitto__send_puback(mosq, message->msg.mid);
			pthread_mutex_lock(&mosq->callback_mutex);
			if(mosq->on_message){
				mosq->in_callback = true;
				mosq->on_message(mosq, mosq->userdata, &message->msg);
				mosq->in_callback = false;
			}
			pthread_mutex_unlock(&mosq->callback_mutex);
			mosquitto__message_cleanup(&message);
			return rc;
		case 2:
			rc = mosquitto__send_pubrec(mosq, message->msg.mid);
			pthread_mutex_lock(&mosq->in_message_mutex);
			message->state = mosq_ms_wait_for_pubrel;
			mosquitto__message_queue(mosq, message, mosq_md_in);
			pthread_mutex_unlock(&mosq->in_message_mutex);
			return rc;
		default:
			mosquitto__message_cleanup(&message);
			return MOSQ_ERR_PROTOCOL;
	}
}

