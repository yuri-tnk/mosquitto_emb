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

#if defined WIN32

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <windows.h>
#include "tn_alloc.h"

#define  lock()      EnterCriticalSection(&mi->csec)
#define  unlock()    LeaveCriticalSection(&mi->csec)

#define TERR_NO_ERR     0
#define TERR_WPARAM   (-3)

#elif defined __linux__

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>

#include "tn_alloc.h"

#define FALSE  0
#define TRUE   1

#define MIN(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a < _b ? _a : _b; })

#define  lock()      pthread_mutex_lock(&mi->mtx)
#define  unlock()    pthread_mutex_unlock(&mi->mtx)

#define TERR_NO_ERR           0
#define TERR_WPARAM         (-3)

#define u_printf  printf

#else  // RTOS

#include <string.h>
#include "tn_config.h"
#include "tn.h"
#include "tn_utils.h"

#if defined TN_TEST
#include "test.h"
#endif

#define  lock()   if(tn_system_state == TN_ST_STATE_RUNNING)\
                  {  (void)tn_sem_acquire(&mi->m_sem, TN_WAIT_INFINITE); }

#define  unlock() if(tn_system_state == TN_ST_STATE_RUNNING)\
                  { (void)tn_sem_signal(&mi->m_sem); }

int u_printf(const char *fmt, ... );
void soft_reset(void);

#endif

#define M_ALIG             sizeof(MEMHDR) //8UL
#define MIN_POOL_SIZE     48UL

static int do_deallocate(MEMINFO * mi, void * p_mem);
static void * do_allocate(MEMINFO * mi, long need_size);
static void * do_reallocate(MEMINFO * mi, void * p_mem, unsigned long new_size);

//----------------------------------------------------------------------------
int tn_alloc_init(MEMINFO * mi, unsigned char * buf, unsigned int buf_size)
{
    int rc;
    unsigned long tmp;
    unsigned long a_buf_size;
    if(mi == NULL || buf == NULL || buf_size < MIN_POOL_SIZE)
    {
        rc = TERR_WPARAM;
    }
    else
    {
        tmp = (unsigned long)buf;
        // actual buf start addr must be aligned
        mi->buf_start_addr =  (tmp +(M_ALIG-1UL)) & (~(M_ALIG-1UL));
        // after align, the buf start addr may be increased and an actual buf size
        // will be reduced in this case
        a_buf_size = buf_size - (tmp - mi->buf_start_addr);
        a_buf_size &= ~(M_ALIG - 1UL);  // actual buf size is also aligned
        mi->buf_last_addr = mi->buf_start_addr + a_buf_size - M_ALIG;

        mi->f_next       = (MEMHDR *)(mi->buf_start_addr);
        mi->f_next->next = NULL;
        mi->f_next->size = (long)a_buf_size;
        mi->t_free       = (long)a_buf_size;
        mi->t_min_mem    = mi->t_free;


#if defined WIN32
        InitializeCriticalSection(&mi->csec);
        rc = 0;
#elif defined __linux__
        pthread_mutex_init(&mi->mtx, NULL);
        rc = 0;
#else
        mi->m_sem.id_sem = 0UL;
        rc = tn_sem_create(&mi->m_sem, 1, 1);
#endif
    }
    return rc;
}


//----------------------------------------------------------------------------
void * tn_alloc(MEMINFO * mi, long alloc_size)
{
    void * ret_val = NULL;
    if(mi != NULL && alloc_size > 0L)
    {
        lock();
        ret_val = do_allocate(mi, alloc_size);
        unlock();

        if(ret_val == NULL)
        {
            u_printf("========= OUT OF MEM ======== Req: %ld  Free: %ld\r\n", 
                      alloc_size, 
                      tn_alloc_get_free_size(mi));
#if defined WIN32 || defined __linux__
            exit(0);
#else
            tn_task_sleep(200);
            soft_reset();
#endif
        }
        else
        {
//   if(tn_system_state == TN_ST_STATE_RUNNING)
//   {
//      u_printf(("==== tn_alloc: %d\r\n", alloc_size);
//   }
        }

    }
    return ret_val;
}

//----------------------------------------------------------------------------
int tn_dealloc(MEMINFO * mi, void * p_mem)
{
    int rc = TERR_WPARAM;
    if(mi != NULL && p_mem != NULL)
    {
        lock();
        rc = do_deallocate(mi, p_mem);
        unlock();
    }

    return rc;
}

//----------------------------------------------------------------------------
long tn_alloc_usable_size(MEMINFO * mi, void * p_mem)
{
    MEMHDR * block;
    long ret = 0;
    unsigned long block_start_addr;

    lock();

    block_start_addr = (unsigned long)((char*)p_mem);
    block_start_addr -= M_ALIG; // Get header
    block =  (MEMHDR *)block_start_addr;
    ret = block->size;

    unlock();

    return ret;
}

//----------------------------------------------------------------------------
static int do_deallocate(MEMINFO * mi, void * p_mem)
{
    MEMHDR * ptr;
    MEMHDR * ptr_tmp;
    MEMHDR * block;
    MEMHDR * ptr_prev = NULL;
    int rc = 0;
    int fExit = FALSE;
    unsigned long block_start_addr;
    unsigned long block_last_addr;
    unsigned long curr_start_addr;
    unsigned long curr_last_addr;
    unsigned long next_start_addr;
    unsigned long tmp;

    block_start_addr = (unsigned long)((char*)p_mem);
    block_start_addr -= M_ALIG; // Get header
    block =  (MEMHDR *)block_start_addr;
    block_last_addr  = block_start_addr + (unsigned long)block->size - M_ALIG;

    if((((unsigned long)block->size & (M_ALIG - 1UL)) != 0UL) ||   // bad align
            block->next != NULL || // memory corrupted
            block_start_addr < mi->buf_start_addr ||
            block_last_addr > mi->buf_last_addr)
    {
        rc = -1;
    }
    else
    {
        if(mi->f_next == NULL)   // no free blocks
        {
            mi->f_next = block;
            mi->t_free += block->size;
        }
        else
        {
            for(ptr = mi->f_next; ptr != NULL; ptr = ptr->next)
            {
                curr_start_addr = (unsigned long)ptr;
                curr_last_addr  = curr_start_addr + (unsigned long)ptr->size - M_ALIG;

                if(block_start_addr < curr_start_addr)
                {
                    if(block_last_addr >= curr_start_addr)
                    {
                        rc = -1;
                    }
                    else  // <
                    {
                        if(block_last_addr + M_ALIG == curr_start_addr)
                        {
                            // B1 merge end of the block with the current block start
                            mi->t_free += block->size;
                            if(ptr_prev == NULL)  // no prev
                            {
                                // B1_1
                                ptr_tmp = mi->f_next->next;
                                mi->f_next   = block;
                                mi->f_next->next = ptr_tmp;
                            }
                            else
                            {
                                // B1_2
                                ptr_tmp = ptr_prev->next;
                                ptr_prev->next = block;
                                block->next = ptr_tmp;
                            }
                            block->size += ptr->size;
                        }
                        else
                        {
                            // B2 insert before current
                            mi->t_free += block->size;

                            if(ptr_prev == NULL)  // no prev
                            {
                                // B2_1
                                mi->f_next = block;
                            }
                            else
                            {
                                //B2_2
                                ptr_prev->next = block;
                            }

                            block->next = ptr;
                        }
                    }
                    fExit = TRUE;
                }
                else if(block_start_addr == curr_start_addr)
                {
                    rc = -1;
                    fExit = TRUE;
                }
                else  // >
                {
                    next_start_addr = (unsigned long)ptr->next;
                    if(next_start_addr != 0UL)
                    {
                        if(block_start_addr < next_start_addr)
                        {
                            if(block_last_addr >= next_start_addr)
                            {
                                rc = -1;
                            }
                            else // <
                            {
                                if(block_last_addr + M_ALIG == next_start_addr)
                                {
                                    if(block_start_addr == curr_last_addr + M_ALIG)
                                    {
                                        mi->t_free += block->size;
                                        // B3 merge begin of the block with end of current and
                                        // merge end of block with begin  of next
                                        ptr->size += block->size;
                                        tmp = (unsigned long)ptr->next->size;
                                        ptr->size += (long)tmp;
                                        ptr->next = ptr->next->next;
                                    }
                                    else
                                    {
                                        mi->t_free += block->size;
                                        // B4 merge end of block with begin  of next
                                        tmp = (unsigned long)ptr->next->size;
                                        ptr_tmp = ptr->next->next;
                                        ptr->next = block;
                                        ptr->next->size += (long)tmp;
                                        block->next = ptr_tmp;
                                    }
                                }
                                else
                                {
                                    if(block_start_addr == curr_last_addr + M_ALIG)
                                    {
                                        mi->t_free += block->size;
                                        // B5 merge start of the block with end of the current
                                        ptr->size += block->size;
                                    }
                                    else
                                    {
                                        mi->t_free += block->size;
                                        // B6 insert block after current
                                        ptr_tmp = ptr->next;
                                        ptr->next = block;
                                        block->next = ptr_tmp;
                                    }
                                }
                            }
                            fExit = TRUE;
                        } // if not,continue
                    }
                    else // == 0  there is no next free block in the list
                    {
                        if(block_start_addr > curr_last_addr)
                        {
                            if(block_start_addr == curr_last_addr + M_ALIG)
                            {
                                mi->t_free += block->size;
                                // B7 merge start of the block with end of the current
                                ptr->size += block->size;
                            }
                            else
                            {
                                mi->t_free += block->size;
                                // B8 insert block after current
                                ptr_tmp = ptr->next;
                                ptr->next = block;
                                block->next = ptr_tmp;
                            }
                        }
                        else
                        {
                            rc = -1;
                        }
                        fExit = TRUE;
                    }
                }

                if(fExit == TRUE)
                {
                    break;
                }
                ptr_prev = ptr;
            }
        }
    }

    return rc;
}

//----------------------------------------------------------------------------
static void * do_allocate(MEMINFO * mi, long need_size)
{
    MEMHDR * ptr;
    MEMHDR * new_block;
    MEMHDR * ret_block = NULL;
    MEMHDR * ptr_prev = NULL;
    long a_size;
    long curr_size;
    unsigned long tmp;

// Min block size - Hdr + M_Align = 16 bytes
#define MIN_SPLIT  16L //24L

    tmp = (((unsigned long)need_size + (M_ALIG - 1UL)) & (~(M_ALIG-1UL)));
    a_size = (long)tmp + (long)M_ALIG; // Actual alloc size

    for(ptr = mi->f_next; ptr != NULL; ptr = ptr->next)
    {
        curr_size = ptr->size;
        if(curr_size >= a_size)
        {
            tmp  = (unsigned long)ptr;
            ret_block = (MEMHDR *)tmp;

            if(curr_size - a_size  >= MIN_SPLIT)  // split block
            {
                tmp += (unsigned long)a_size;
                new_block = (MEMHDR *)tmp;
                new_block->next = ptr->next;
                new_block->size = curr_size - a_size;

                if(ptr_prev == NULL)
                {
                    mi->f_next = new_block;
                }
                else
                {
                    ptr_prev->next = new_block;
                }

                ret_block->size = a_size;
                mi->t_free -= a_size;
                if(mi->t_min_mem > mi->t_free)
                {
                     mi->t_min_mem = mi->t_free;
                }
            }
            else // remove an overall block from the list
            {
                if(ptr_prev == NULL)
                {
                    mi->f_next = ptr->next; // May be NULL
                }
                else
                {
                    ptr_prev->next = ptr->next;
                }
                ret_block->size = ptr->size;
                mi->t_free -= ptr->size;
                if(mi->t_min_mem > mi->t_free)
                {
                     mi->t_min_mem = mi->t_free;
                }
            }

            ret_block->next = NULL;

            break;
        }
        ptr_prev = ptr;
    }
    tmp  = (unsigned long)ret_block;
    if(tmp > 0UL)
    {
        tmp += M_ALIG;
    }
    return (void*)((char*)tmp);
}

//----------------------------------------------------------------------------
long tn_alloc_get_free_size(MEMINFO * mi)
{
    long rc = 0;
    lock();
    if(mi != NULL)
    {
        rc = mi->t_free;
    }
    unlock();
    return rc;
}

//----------------------------------------------------------------------------
long tn_alloc_get_min_free_size(MEMINFO * mi)
{
    long rc = 0;
    lock();
    if(mi != NULL)
    {
        rc = mi->t_min_mem;
    }
    unlock();
    return rc;
}

//----------------------------------------------------------------------------
void * tn_realloc(MEMINFO * mi, void * p_mem, long new_size)
{
    void * ret_val = NULL;
    if(mi != NULL && new_size > 0L)
    {
        lock();
        ret_val = do_reallocate(mi, p_mem, (unsigned long)new_size);
        unlock();
    }

    return ret_val;
}

//----------------------------------------------------------------------------
static void * do_reallocate(MEMINFO * mi, void * p_mem, unsigned long new_size)
{
    MEMHDR * block;
    unsigned long block_start_addr;
    unsigned long nbytes_to_copy;

    void * ret_ptr = NULL;

    if(p_mem == NULL) // just call do_allocate()
    {
        ret_ptr = do_allocate(mi, (long)new_size);
    }
    else
    {
        // First, find payload size of 'p_mem'

        block_start_addr = (unsigned long)((char*)p_mem);
        block_start_addr -= M_ALIG; // Get header
        block =  (MEMHDR *)block_start_addr;

        nbytes_to_copy = block->size - (long)M_ALIG;
        nbytes_to_copy = MIN(nbytes_to_copy, new_size);

        ret_ptr = do_allocate(mi, (long)new_size);
        if(ret_ptr != NULL)
        {
            //-- Copy old mem
            memmove(ret_ptr, p_mem, nbytes_to_copy);
            //-- Free old mem
            do_deallocate(mi, p_mem);
        }
    }
    return ret_ptr;
}



#if defined WIN32
//----------------------------------------------------------------------------
void tdump(MEMINFO * mi)
{
    MEMHDR * ptr;
    u_printf("f_next: %08X mi->t_free: %d ",mi->f_next, mi->t_free);
    if(mi->f_next)
        u_printf("f_next->next: %08X f_next->size: %d\n",
               mi->f_next->next, mi->f_next->size);
    else
        u_printf("\n");

    for(ptr = mi->f_next; ptr != NULL; ptr = ptr->next)
    {
        u_printf("ptr: %08X ptr->next: %08X ptr->size: %d  \n",
               ptr, ptr->next, ptr->size);
    }
}
#else

#if defined TN_TEST

void tdump(MEMINFO * mi)
{
    MEMHDR * ptr;

    TestPrint("f_next: %08X mi->t_free: %d ",mi->f_next, mi->t_free);
    if(mi->f_next != NULL)
    {
        TestPrint("f_next->next: %08X f_next->size: %d\r\n",
                  mi->f_next->next, mi->f_next->size);
    }
    else
    {
        TestPrint("\r\n");
    }

    for(ptr = mi->f_next; ptr != NULL; ptr = ptr->next)
    {
        TestPrint("ptr: %08X ptr->next: %08X ptr->size: %d  \r\n",
                  ptr, ptr->next, ptr->size);
    }
}
#endif

#endif

//----------------------------------------------------------------------------
//----------------------------------------------------------------------------
//----------------------------------------------------------------------------
//----------------------------------------------------------------------------

