/**
*
*  Copyright (c) 2004, 2016 Yuri Tiomkin
*  All Rights Reserved
*
*
*  Permission to use, copy, modify, and distribute this software in source
*  and binary forms and its documentation for any purpose and without fee
*  is hereby granted, provided that the above copyright notice appear
*  in all copies and that both that copyright notice and this permission
*  notice appear in supporting documentation.
*
*
*  THIS SOFTWARE IS PROVIDED BY YURI TIOMKIN "AS IS" AND ANY EXPRESSED OR
*  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
*  OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
*  IN NO EVENT SHALL YURI TIOMKIN OR ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
*  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
*  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
*  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
*  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
*  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
*  IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
*  THE POSSIBILITY OF SUCH DAMAGE.
*
*/

#ifndef TN_ALLOC_H_
#define TN_ALLOC_H_

typedef struct _MEMHDR 
{
   struct _MEMHDR * next;
   long size;
}MEMHDR;

typedef struct _MEMINFO
{
   MEMHDR * f_next;
   long t_free;
   long t_min_mem;

   unsigned long buf_start_addr;
   unsigned long buf_last_addr;
#if defined WIN32
   CRITICAL_SECTION csec;
#elif defined __linux__
   pthread_mutex_t mtx;
#else
   TN_SEM  m_sem;
#endif

}MEMINFO;

int tn_alloc_init(MEMINFO * mi, unsigned char * buf, unsigned int buf_size);
void * tn_alloc(MEMINFO * mi, long alloc_size);
void * tn_realloc(MEMINFO * mi, void * p_mem, long new_size);
int tn_dealloc(MEMINFO * mi, void * p_mem);
long tn_alloc_usable_size(MEMINFO * mi, void * p_mem);
long tn_alloc_get_free_size(MEMINFO * mi);
long tn_alloc_get_min_free_size(MEMINFO * mi);


#endif
