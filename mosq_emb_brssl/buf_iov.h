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

#ifndef BUF_IOV_H_
#define BUF_IOV_H_

typedef struct _VLISTENTRY
{
   struct _VLISTENTRY * next;
   int buf_len;
   unsigned char buf[1];
}VLISTENTRY;

typedef struct _VLISTROOT
{
    int fbuf_pos;
    VLISTENTRY * head;
    VLISTENTRY * tail;

}VLISTROOT;


void vlist_init(VLISTROOT * root);
void vlist_clear_all(VLISTROOT * root);
void vlist_remove_first(VLISTROOT * root);
VLISTENTRY * vlist_get_first(VLISTROOT * root); //always 1st
VLISTENTRY * vlist_get_last(VLISTROOT * root);
int vlist_add_last(VLISTROOT * root, int len);

int read_v(VLISTROOT * lst, unsigned char * out_buf, int nread);
int write_v(VLISTROOT * lst, unsigned char * in_buf, int nwrite); 

#endif /* #ifndef BUF_IOV_H_ */
