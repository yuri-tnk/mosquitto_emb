/*
Copyright (c) 2013,2014 Roger Light <roger@atchoo.org>

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

#ifdef __APPLE__
#include <mach/mach.h>
#include <mach/mach_time.h>
#endif

#include <unistd.h>
#include <time.h>

#include "mosquitto_emb.h"
#include "time_mosq.h"


time_t mosquitto_time(void)
{
	struct timespec tp;

	clock_gettime(CLOCK_MONOTONIC, &tp);
	return tp.tv_sec;

//	return time(NULL);
}

