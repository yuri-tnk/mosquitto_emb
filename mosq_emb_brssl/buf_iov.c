/*

Copyright © 2004,2021 Yuri Tiomkin
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

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "buf_iov.h"

void *mosquitto__malloc(size_t size);
void mosquitto__free(void *mem);

#define xmalloc mosquitto__malloc
#define xfree   mosquitto__free

#ifdef __linux__
#define u_printf printf
#endif
//----------------------------------------------------------------------------
void vlist_init(VLISTROOT * root)
{
   root->fbuf_pos = 0;
   root->head = NULL;
   root->tail = NULL;
}

//----------------------------------------------------------------------------
void vlist_clear_all(VLISTROOT * root)
{
    for(;;)
    {
        VLISTENTRY * entry = vlist_get_first(root);
        if(entry == NULL)
        {
            break;
        }
        else
        {
            vlist_remove_first(root);
        }
    }
}

//----------------------------------------------------------------------------
void vlist_remove_first(VLISTROOT * root)
{
    VLISTENTRY * entry = root->head;

    if(root->head != NULL)
    {
        root->head = root->head->next;
    }

    if(entry != NULL)
    {
        xfree(entry);
    }
}

//----------------------------------------------------------------------------
VLISTENTRY * vlist_get_first(VLISTROOT * root) //always 1st
{
    return root->head;
}

//----------------------------------------------------------------------------
VLISTENTRY * vlist_get_last(VLISTROOT * root)
{
    return root->tail;
}

//----------------------------------------------------------------------------
int vlist_add_last(VLISTROOT * root, int len)
{
    int rc = 0;

    VLISTENTRY * entry = (VLISTENTRY *)xmalloc(sizeof(VLISTENTRY) + len);
    if(entry == NULL)
    {
        rc = -1;
    }
    else
    {
        entry->next      = NULL;
        entry->buf_len   = len;

        if(root->head == NULL) // Empty
        {
            root->head = entry;
            root->tail = root->head;
        }
        else
        {
            root->tail->next = entry;
            root->tail       = entry;
        }
    }
    return rc;
}

//----------------------------------------------------------------------------
int read_v(VLISTROOT * lst, unsigned char * out_buf, int nread)
{
    int fExit = false;
    int fDelBuf = false;
    VLISTENTRY * ptr = NULL;
    int nrd = nread;
    int nb;
    int pos = 0;

    while(fExit == false)
    {
        ptr = vlist_get_first(lst);
        if(ptr != NULL)
        {
            int fbuf_aval = ptr->buf_len - lst->fbuf_pos;
            if(fbuf_aval <= 0)
            {
                u_printf("vlist: Internal err 1\n");
                pos = -1;
                fExit = true;
            }
            else
            {
                if(nrd >= fbuf_aval)
                {
                    nb = fbuf_aval;
                    fDelBuf = true;
                }
                else
                {
                    nb = nrd;
                }

                memcpy(&out_buf[pos], &ptr->buf[lst->fbuf_pos], nb);
                nrd -= nb;
                pos += nb;

                if(fDelBuf == true)
                {
                   fDelBuf = false;

                   vlist_remove_first(lst);

                   lst->fbuf_pos = 0;
                }
                else
                {
                    lst->fbuf_pos += nb;
                }

                if(nrd == 0) // Finished rd
                {
                    fExit = true;
                }
            }
        }
        else // if we want to read more that list contains now
        {
            fExit = true;
        }
    }
    return pos;
}

//----------------------------------------------------------------------------
int write_v(VLISTROOT * lst, unsigned char * in_buf, int nwrite)
{
    int rc = 0;
    VLISTENTRY * ptr = NULL;

    if(in_buf == NULL || nwrite <= 0)
    {
        rc = -1;
    }
    else
    {
        rc = vlist_add_last(lst, nwrite);
        if(rc == 0)
        {
            ptr = vlist_get_last(lst);
            if(ptr != NULL)
            {
                memcpy(&ptr->buf[0], in_buf, nwrite);
                rc = nwrite;
            }
        }
    }
    return rc;
}

//----------------------------------------------------------------------------
//----------------------------------------------------------------------------
//----------------------------------------------------------------------------
//----------------------------------------------------------------------------
//----------------------------------------------------------------------------
 