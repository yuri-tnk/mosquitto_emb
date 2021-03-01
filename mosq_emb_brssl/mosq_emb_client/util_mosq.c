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
#include <string.h>



#include "mosquitto_emb.h"
#include "memory_mosq.h"
#include "net_mosq.h"
#include "send_mosq.h"
#include "time_mosq.h"
//#include "tls_mosq.h>
#include "util_mosq.h"

int mosquitto__packet_alloc(struct mosquitto__packet *packet)
{
    uint8_t remaining_bytes[5], byte;
    uint32_t remaining_length;
    int i;

    assert(packet);

    remaining_length = packet->remaining_length;
    packet->payload = NULL;
    packet->remaining_count = 0;
    do
    {
        byte = remaining_length % 128;
        remaining_length = remaining_length / 128;
        /* If there are more digits to encode, set the top bit of this digit */
        if(remaining_length > 0)
        {
            byte = byte | 0x80;
        }
        remaining_bytes[packet->remaining_count] = byte;
        packet->remaining_count++;
    }
    while(remaining_length > 0 && packet->remaining_count < 5);

    if(packet->remaining_count == 5)
        return MOSQ_ERR_PAYLOAD_SIZE;
    packet->packet_length = packet->remaining_length + 1 + packet->remaining_count;
    packet->payload = mosquitto__malloc(sizeof(uint8_t)*packet->packet_length);
    if(!packet->payload)
        return MOSQ_ERR_NOMEM;

    packet->payload[0] = packet->command;
    for(i=0; i<packet->remaining_count; i++)
    {
        packet->payload[i+1] = remaining_bytes[i];
    }
    packet->pos = 1 + packet->remaining_count;

    return MOSQ_ERR_SUCCESS;
}

// from 2.0.7
int mosquitto__check_keepalive(struct mosquitto *mosq)
{
	time_t next_msg_out;
	time_t last_msg_in;
	time_t now;
	int rc;

	enum mosquitto_client_state state;

	assert(mosq);

	now = mosquitto_time();

	pthread_mutex_lock(&mosq->msgtime_mutex);
	next_msg_out = mosq->next_msg_out;
	last_msg_in = mosq->last_msg_in;
	pthread_mutex_unlock(&mosq->msgtime_mutex);

//u_printf(" keepalive: %u now: %lu next_msg_out: %lu last_msg_in: %lu  ping_t: %lu\n",
//      mosq->keepalive, now, next_msg_out, last_msg_in, mosq->ping_t);

	if(mosq->keepalive && mosq->sock != INVALID_SOCKET &&
			(now >= next_msg_out || now - last_msg_in >= mosq->keepalive))
    {

		state = mosquitto__get_state(mosq);
		if(state == mosq_cs_connected /*mosq_cs_active*/ && mosq->ping_t == 0)
        {
			//send__pingreq(mosq);
	mosquitto__send_pingreq(mosq);

			/* Reset last msg times to give the server time to send a pingresp */
			pthread_mutex_lock(&mosq->msgtime_mutex);
			mosq->last_msg_in = now;
			mosq->next_msg_out = now + mosq->keepalive;
			pthread_mutex_unlock(&mosq->msgtime_mutex);
		}
        else
        {
//u_printf("==========state: %d\n", state);
			mosquitto__socket_close(mosq);
			state = mosquitto__get_state(mosq);
			if(state == mosq_cs_disconnecting)
            {
				rc = MOSQ_ERR_SUCCESS;
			}
            else
            {
				rc = MOSQ_ERR_KEEPALIVE;
			}

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
	}
	return MOSQ_ERR_SUCCESS;
}

uint16_t mosquitto__mid_generate(struct mosquitto *mosq)
{
    /* FIXME - this would be better with atomic increment, but this is safer
     * for now for a bug fix release.
     *
     * If this is changed to use atomic increment, callers of this function
     * will have to be aware that they may receive a 0 result, which may not be
     * used as a mid.
     */
    uint16_t mid;
    assert(mosq);

    pthread_mutex_lock(&mosq->mid_mutex);
    mosq->last_mid++;
    if(mosq->last_mid == 0)
        mosq->last_mid++;
    mid = mosq->last_mid;
    pthread_mutex_unlock(&mosq->mid_mutex);

    return mid;
}

/* Check that a topic used for publishing is valid.
 * Search for + or # in a topic. Return MOSQ_ERR_INVAL if found.
 * Also returns MOSQ_ERR_INVAL if the topic string is too long.
 * Returns MOSQ_ERR_SUCCESS if everything is fine.
 */
int mosquitto_pub_topic_check(const char *str)
{
    int len = 0;
    while(str && str[0])
    {
        if(str[0] == '+' || str[0] == '#')
        {
            return MOSQ_ERR_INVAL;
        }
        len++;
        str = &str[1];
    }
    if(len > 65535)
        return MOSQ_ERR_INVAL;

    return MOSQ_ERR_SUCCESS;
}

/* Check that a topic used for subscriptions is valid.
 * Search for + or # in a topic, check they aren't in invalid positions such as
 * foo/#/bar, foo/+bar or foo/bar#.
 * Return MOSQ_ERR_INVAL if invalid position found.
 * Also returns MOSQ_ERR_INVAL if the topic string is too long.
 * Returns MOSQ_ERR_SUCCESS if everything is fine.
 */
int mosquitto_sub_topic_check(const char *str)
{
    char c = '\0';
    int len = 0;
    while(str && str[0])
    {
        if(str[0] == '+')
        {
            if((c != '\0' && c != '/') || (str[1] != '\0' && str[1] != '/'))
            {
                return MOSQ_ERR_INVAL;
            }
        }
        else if(str[0] == '#')
        {
            if((c != '\0' && c != '/')  || str[1] != '\0')
            {
                return MOSQ_ERR_INVAL;
            }
        }
        len++;
        c = str[0];
        str = &str[1];
    }
    if(len > 65535)
        return MOSQ_ERR_INVAL;

    return MOSQ_ERR_SUCCESS;
}

/* Does a topic match a subscription? */
int mosquitto_topic_matches_sub(const char *sub, const char *topic, bool *result)
{
    int slen, tlen;
    int spos, tpos;
    bool multilevel_wildcard = false;

    if(!sub || !topic || !result)
        return MOSQ_ERR_INVAL;

    slen = strlen(sub);
    tlen = strlen(topic);

    if(slen && tlen)
    {
        if((sub[0] == '$' && topic[0] != '$')
                || (topic[0] == '$' && sub[0] != '$'))
        {

            *result = false;
            return MOSQ_ERR_SUCCESS;
        }
    }

    spos = 0;
    tpos = 0;

    while(spos < slen && tpos < tlen)
    {
        if(sub[spos] == topic[tpos])
        {
            if(tpos == tlen-1)
            {
                /* Check for e.g. foo matching foo/# */
                if(spos == slen-3
                        && sub[spos+1] == '/'
                        && sub[spos+2] == '#')
                {
                    *result = true;
                    multilevel_wildcard = true;
                    return MOSQ_ERR_SUCCESS;
                }
            }
            spos++;
            tpos++;
            if(spos == slen && tpos == tlen)
            {
                *result = true;
                return MOSQ_ERR_SUCCESS;
            }
            else if(tpos == tlen && spos == slen-1 && sub[spos] == '+')
            {
                spos++;
                *result = true;
                return MOSQ_ERR_SUCCESS;
            }
        }
        else
        {
            if(sub[spos] == '+')
            {
                spos++;
                while(tpos < tlen && topic[tpos] != '/')
                {
                    tpos++;
                }
                if(tpos == tlen && spos == slen)
                {
                    *result = true;
                    return MOSQ_ERR_SUCCESS;
                }
            }
            else if(sub[spos] == '#')
            {
                multilevel_wildcard = true;
                if(spos+1 != slen)
                {
                    *result = false;
                    return MOSQ_ERR_SUCCESS;
                }
                else
                {
                    *result = true;
                    return MOSQ_ERR_SUCCESS;
                }
            }
            else
            {
                *result = false;
                return MOSQ_ERR_SUCCESS;
            }
        }
    }
    if(multilevel_wildcard == false && (tpos < tlen || spos < slen))
    {
        *result = false;
    }

    return MOSQ_ERR_SUCCESS;
}


FILE *mosquitto__fopen(const char *path, const char *mode)
{
    return fopen(path, mode);
}

//----------------------------------------------------------------------------
int mosquitto__set_state(struct mosquitto * mosq,
                         enum mosquitto_client_state state)
{
    pthread_mutex_lock(&mosq->state_mutex);
    mosq->state = state;
    pthread_mutex_unlock(&mosq->state_mutex);

    return MOSQ_ERR_SUCCESS;
}

//----------------------------------------------------------------------------
enum mosquitto_client_state mosquitto__get_state(struct mosquitto * mosq)
{
    enum mosquitto_client_state state;

    pthread_mutex_lock(&mosq->state_mutex);
    state = mosq->state;
    pthread_mutex_unlock(&mosq->state_mutex);

    return state;
}

#if 0
// YVT - ASCII only
//----------------------------------------------------------------------------
int mosquitto_username_pw_set(struct mosquitto * mosq,
                              const char * username,
                              const char *password)
{
    size_t slen;

    if(!mosq)
        return MOSQ_ERR_INVAL;

    if(mosq->protocol == mosq_p_mqtt311 || mosq->protocol == mosq_p_mqtt31)
    {
        if(password != NULL && username == NULL)
        {
            return MOSQ_ERR_INVAL;
        }
    }

    mosquitto__free(mosq->username);
    mosq->username = NULL;

    mosquitto__free(mosq->password);
    mosq->password = NULL;

    if(username)
    {
        slen = strlen(username);
        if(slen > UINT16_MAX)
        {
            return MOSQ_ERR_INVAL;
        }
        //if(mosquitto_validate_utf8(username, (int)slen))
        //{
        //    return MOSQ_ERR_MALFORMED_UTF8;
        //}
        mosq->username = mosquitto__strdup(username);
        if(!mosq->username)
            return MOSQ_ERR_NOMEM;
    }

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
    return MOSQ_ERR_SUCCESS;
}
#endif
