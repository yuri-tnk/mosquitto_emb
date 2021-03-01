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
#include <stdint.h>
#include <unistd.h>

#include "brssl.h"
#include "mosquitto_emb.h"
#include "tn_alloc.h"

/*
 ToDo
     update mosq set_state for all cases from 2.0.7
     add ssl delete resources
*/

#define  USE_SSL 1

struct mosquitto * g_mosq;
static void mqtt_on_message(struct mosquitto * mosq,
                            void * userdata,
                            const struct mosquitto_message * msg);

static void mqtt_on_log(struct mosquitto *mosq, void *obj, int level, const char *str);

int g_mqtt_keepalive     = 60;

//#define CERTS_ROOT_DIR  "/mnt/hgfs/Linux_shared/"
#define CERTS_ROOT_DIR  "/home/yurit/Projects/mosquitto_emb/"

const char g_send_str[] = "Message from mosq client emb ";

#ifdef  USE_SSL

int16_t g_mqtt_port = 8883;

//#define AWS_MQTT 1


#ifdef AWS_MQTT


int qos = 1;

#define HARDWARE_NAME     "Demo"   // Put your project related value here 
#define FIRMWARE_VERSION  "1.1.1"  // Put your project related value here 

const char g_topic[]     = "$aws/things/xxx/shadow/update/delta"; // Put your project related value here 
const char g_topic_pub[] = "$aws/things/xx/shadow/update";        // Put your project related value here 
const char g_mqtt_host[] = "xxx.iot.us-west-2.amazonaws.com"; // Put your actual AWS IoT server name
const char * g_sni       = g_mqtt_host;

const char g_ca_name[]   = CERTS_ROOT_DIR "mosq_emb_brssl/certs/aws_ca.crt";       // Put your project related file here 
const char g_key_name[]  = CERTS_ROOT_DIR "mosq_emb_brssl/certs/aws_cli_key.key";  // Put your project related file here 
const char g_cert_name[] = CERTS_ROOT_DIR "mosq_emb_brssl/certs/aws_cli_cert.crt"; // Put your project related file here 

#else // not AWS

int qos = 2;

const char g_topic[]     = "em/zaq";
const char g_topic_pub[] = "em/qaz";
const char g_mqtt_host[] = "127.0.0.1";
const char g_sni[] = {0, 0, 0, 0}; // No use SNI - local machine debug

const char g_ca_name[]   = CERTS_ROOT_DIR "mosq_emb_brssl/certs/serverca.crt";
const char g_key_name[]  = CERTS_ROOT_DIR "mosq_emb_brssl/certs/client.key";
const char g_cert_name[] = CERTS_ROOT_DIR "mosq_emb_brssl/certs/client.crt";

#endif

#else //No SSL

int qos = 2;

int16_t g_mqtt_port = 1883;

const char g_topic[]     = "em/zaq";
const char g_topic_pub[] = "em/qaz";
const char g_mqtt_host[] = "127.0.0.1";

#endif

//--- Memory blocks for Mosquitto && BearSSL - to check a real memory consumption

MEMINFO g_mosquitto_memory;
unsigned char * g_m_mem_buf = NULL; 
unsigned int g_m_mem_buf_size = (1024 * 48);

MEMINFO g_brssl_memory;
unsigned char * g_b_mem_buf = NULL; 
unsigned int g_b_mem_buf_size = (1024 * 48);

//----------------------------------------------------------------------
int main(int argc, const char ** argv)
{
    int rc;
    int mid;
    int cnt = 0;
    int n_loop = 0;
    long min_free_mem;
    char send_buf[512];

//--------- Allocate memory blocks and init memory managers

    g_m_mem_buf = (unsigned char *)malloc(g_m_mem_buf_size);
    if(g_m_mem_buf == NULL)
    {
        u_printf("malloc() failed - 1\n");
        exit(0); 
    }
    rc = tn_alloc_init(&g_mosquitto_memory, g_m_mem_buf, g_m_mem_buf_size);
    if(rc != 0)
    {
        u_printf("tn_alloc_init() failed - 1\n");
        exit(0); 
    }

    g_b_mem_buf = (unsigned char *)malloc(g_b_mem_buf_size);
    if(g_m_mem_buf == NULL)
    {
        u_printf("malloc() failed - 2\n");
        exit(0); 
    }
    rc = tn_alloc_init(&g_brssl_memory, g_b_mem_buf, g_b_mem_buf_size);
    if(rc != 0)
    {
        u_printf("tn_alloc_init() failed - 2\n");
        exit(0); 
    }
//------------------------

    g_mosq = mosquitto_new(NULL,  //id,
                           true,  //clean_session,
                           NULL); //user_data);

    mosquitto_message_callback_set(g_mosq, mqtt_on_message);
    mosquitto_log_callback_set(g_mosq, mqtt_on_log);

 //---------- If SSL is used -----------------------

#ifdef  USE_SSL
    
    mosquitto_set_brssl_param(g_mosq,
                              (char *) g_ca_name,
	                          (char *) g_cert_name,
	                          (char *) g_key_name,
                              (char *) g_sni,
                              true);   //int verbose) 
#endif

 //-------------------------------------------------

    rc = mosquitto_connect(g_mosq,
                           g_mqtt_host,         //const char *host,
                           g_mqtt_port,         // int port,
                           g_mqtt_keepalive);   // int keepalive);

    if(rc == MOSQ_ERR_SUCCESS)
    {
        rc = mosquitto_loop_start(g_mosq);
        if(rc != MOSQ_ERR_SUCCESS)
        {
            u_printf( "mosquitto_loop_start() failed %d\n", rc);
            rc = -1;
        }
        else
        {
            // Subscribes to the topic
            rc = mosquitto_subscribe(g_mosq,
                                     &mid, //int *mid,
                                     g_topic, // const char *sub,
                                     qos); //int qos);
            if(rc != MOSQ_ERR_SUCCESS)
            {
                u_printf( "Fatal: failed to subscribe to topic \'%s\'\n", g_topic);
                rc = -1;
            }
            else
            {
                u_printf( "MQTT: subscribe to \'%s\' - accepted (but not yet really connected)\n", g_topic);
            }
         }
     }
     else
     {
         u_printf("mosquitto_connect: %d\n", rc);
     }

    
    for(n_loop = 0; n_loop < 10; n_loop++)
    {
       cnt++;
       usleep(1000000*10);

#ifdef AWS_MQTT
       sprintf(send_buf, "{\"state\":{\"reported\":{\"hardware\":{\"type\":\"%s\",\"firmware_version\":\"%s\"}}}}",
                HARDWARE_NAME, FIRMWARE_VERSION);
#else
       sprintf(send_buf, "%s(%d)", g_send_str, cnt);
#endif
       mosquitto_publish(g_mosq,
                          &mid,
                          g_topic_pub,
                          strlen(send_buf),             // int payloadlen=0,
                          send_buf, // const void *payload=NULL,)
                          0, // qos
                          0);//bool retain);
       u_printf("Sent: %s to \'%s\'\n", send_buf, g_topic_pub);

    }

//-------- Display memory usage

    min_free_mem = tn_alloc_get_min_free_size(&g_mosquitto_memory);
    u_printf("\nMosquitto free mem: %ld min_free_mem: %ld max_in_use: %ld\n",
            tn_alloc_get_free_size(&g_mosquitto_memory),
            min_free_mem,
            g_m_mem_buf_size - min_free_mem);

    min_free_mem = tn_alloc_get_min_free_size(&g_brssl_memory);
    u_printf("\nBearSSL free mem: %ld min_free_mem: %ld max_in_use: %ld\n",
            tn_alloc_get_free_size(&g_brssl_memory),
            min_free_mem,
            g_m_mem_buf_size - min_free_mem);

    return 0;
}

//----------------------------------------------------------------------------
static void mqtt_on_log(struct mosquitto * mosq,
                        void * obj,
                        int level,
                        const char * str)
{
    u_printf("Log: %s\n",str);
}

//----------------------------------------------------------------------------
static void mqtt_on_message(struct mosquitto * mosq,
                            void * userdata,
                            const struct mosquitto_message * msg)
{
    char * pData = NULL;
//    int plen;

    pData = (char*)msg->payload;
  //  plen  =  msg->payloadlen;

    if(strcmp(msg->topic, g_topic) == 0)  // Rx file
    {
        //pData[plen] = 0;
         u_printf("Got msg from topic \'%s\'. Msg: %s\n", msg->topic, pData);
    }
}

//----------------------------------------------------------------------------
//----------------------------------------------------------------------------
//----------------------------------------------------------------------------
//----------------------------------------------------------------------------
//----------------------------------------------------------------------------
//----------------------------------------------------------------------------
//----------------------------------------------------------------------------
