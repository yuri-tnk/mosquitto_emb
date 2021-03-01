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
#ifndef _UTIL_MOSQ_H_
#define _UTIL_MOSQ_H_

#include <stdio.h>

//#include "tls_mosq.h"
#include "mosquitto_emb.h"
#include "mosquitto_internal.h"

int mosquitto__packet_alloc(struct mosquitto__packet *packet);
int mosquitto__check_keepalive(struct mosquitto *mosq);

uint16_t mosquitto__mid_generate(struct mosquitto *mosq);
FILE *mosquitto__fopen(const char *path, const char *mode);

#endif
