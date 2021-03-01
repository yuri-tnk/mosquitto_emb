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

#include <config.h>

#include <stdlib.h>
#include <string.h>

#include "memory_mosq.h"
#include "tn_alloc.h"

//#ifdef REAL_WITH_MEMORY_TRACKING
//#include <malloc.h>
//#endif

//#ifdef REAL_WITH_MEMORY_TRACKING
//static unsigned long memcount = 0;
//static unsigned long max_memcount = 0;
//#endif

extern MEMINFO g_mosquitto_memory;

//----------------------------------------------------------------------------
void *mosquitto__calloc(size_t nmemb, size_t size)
{
    size_t tsize = nmemb * size;
	void * mem = tn_alloc(&g_mosquitto_memory,  tsize);
    if(mem != NULL)
    {
         memset(mem, 0, tsize);
    }

//	void * mem = calloc(nmemb, size);

    

#ifdef REAL_WITH_MEMORY_TRACKING
	memcount += malloc_usable_size(mem);
	if(memcount > max_memcount){
		max_memcount = memcount;
	}
#endif

	return mem;
}

void mosquitto__free(void *mem)
{
	if(mem == NULL)
    {
		return;
	}
    tn_dealloc(&g_mosquitto_memory,  mem);

#ifdef REAL_WITH_MEMORY_TRACKING
	memcount -= malloc_usable_size(mem);
#endif
//	free(mem);
}

void *mosquitto__malloc(size_t size)
{
//	void *mem = malloc(size);
	void * mem = tn_alloc(&g_mosquitto_memory,  size);


#ifdef REAL_WITH_MEMORY_TRACKING
	memcount += malloc_usable_size(mem);
	if(memcount > max_memcount)
    {
		max_memcount = memcount;
	}
#endif

	return mem;
}

#ifdef REAL_WITH_MEMORY_TRACKING
unsigned long mosquitto__memory_used(void)
{
	return memcount;
}

unsigned long mosquitto__max_memory_used(void)
{
	return max_memcount;
}
#endif

void *mosquitto__realloc(void *ptr, size_t size)
{
	void * mem;
#ifdef REAL_WITH_MEMORY_TRACKING
	if(ptr){
		memcount -= malloc_usable_size(ptr);
	}
#endif

	//mem = realloc(ptr, size);
 	mem = tn_realloc(&g_mosquitto_memory, ptr, size);


#ifdef REAL_WITH_MEMORY_TRACKING
	memcount += malloc_usable_size(mem);
	if(memcount > max_memcount){
		max_memcount = memcount;
	}
#endif

	return mem;
}


static char * x_strdup (const char *s)
{
  size_t len = strlen (s) + 1;
  void * new = tn_alloc(&g_mosquitto_memory, len);
  if (new == NULL)
    return NULL;
  return (char *) memcpy (new, s, len);
}

char * mosquitto__strdup(const char *s)
{
	char *str = x_strdup(s);

#ifdef REAL_WITH_MEMORY_TRACKING
	memcount += malloc_usable_size(str);
	if(memcount > max_memcount){
		max_memcount = memcount;
	}
#endif

	return str;
}

