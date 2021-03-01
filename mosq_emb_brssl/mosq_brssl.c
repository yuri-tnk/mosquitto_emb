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

#include <stdbool.h>
#include "brssl.h"

static const uint16_t g_suites[] =
{
    BR_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    BR_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    BR_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    BR_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    BR_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    BR_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    BR_TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
    BR_TLS_ECDHE_ECDSA_WITH_AES_256_CCM,
    BR_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
    BR_TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,
    BR_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
    BR_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
    BR_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
    BR_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
    BR_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
    BR_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    BR_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
    BR_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
    BR_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
    BR_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
    BR_TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
    BR_TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,
    BR_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,
    BR_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
    BR_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,
    BR_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,
    BR_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
    BR_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
    BR_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,
    BR_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,
    BR_TLS_RSA_WITH_AES_128_GCM_SHA256,
    BR_TLS_RSA_WITH_AES_256_GCM_SHA384,
    BR_TLS_RSA_WITH_AES_128_CCM,
    BR_TLS_RSA_WITH_AES_256_CCM,
    BR_TLS_RSA_WITH_AES_128_CCM_8,
    BR_TLS_RSA_WITH_AES_256_CCM_8,
    BR_TLS_RSA_WITH_AES_128_CBC_SHA256,
    BR_TLS_RSA_WITH_AES_256_CBC_SHA256,
    BR_TLS_RSA_WITH_AES_128_CBC_SHA,
    BR_TLS_RSA_WITH_AES_256_CBC_SHA,
    BR_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
    BR_TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
    BR_TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA,
    BR_TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA,
    BR_TLS_RSA_WITH_3DES_EDE_CBC_SHA
};

static const br_hash_class * g_hashes[] =
{
    &br_md5_vtable,
    &br_sha1_vtable,
    &br_sha224_vtable,
    &br_sha256_vtable,
    &br_sha384_vtable,
    &br_sha512_vtable
};

//----------------------------------------------------------------------------
static void cc_start_name_list(const br_ssl_client_certificate_class **pctx)
{
    ccert_context *zc;

    zc = (ccert_context *)pctx;
    if(zc->verbose)
    {
        u_printf( "Server requests a client certificate.\n");
        u_printf( "--- anchor DN list start ---\n");
    }
}

//----------------------------------------------------------------------------
static void cc_start_name(const br_ssl_client_certificate_class ** pctx, size_t len)
{
    ccert_context *zc;

    zc = (ccert_context *)pctx;
    if(zc->verbose)
    {
        u_printf( "new anchor name, length = %u\n",
                  (unsigned)len);
    }
}

//----------------------------------------------------------------------------
static void cc_append_name(const br_ssl_client_certificate_class ** pctx,
                           const unsigned char * data,
                           size_t len)
{
    ccert_context *zc;

    zc = (ccert_context *)pctx;
    if(zc->verbose)
    {
        size_t u;

        for (u = 0; u < len; u ++)
        {
            if (u == 0)
            {
                u_printf( "  ");
            }
            else if (u > 0 && u % 16 == 0)
            {
                u_printf( "\n  ");
            }
            u_printf( " %02x", data[u]);
        }
        if (len > 0)
        {
            u_printf( "\n");
        }
    }
}

//----------------------------------------------------------------------------
static void cc_end_name(const br_ssl_client_certificate_class ** pctx)
{
    (void)pctx;
}

//----------------------------------------------------------------------------
static void cc_end_name_list(const br_ssl_client_certificate_class ** pctx)
{
    ccert_context *zc;

    zc = (ccert_context *)pctx;
    if(zc->verbose)
    {
        u_printf( "--- anchor DN list end ---\n");
    }
}

//----------------------------------------------------------------------------
static void print_hashes(unsigned hh, unsigned hh2)
{
    int i;

    for (i = 0; i < 8; i ++)
    {
        const char *name;

        name = hash_function_name(i);
        if (((hh >> i) & 1) != 0)
        {
            u_printf( " %s", name);
        }
        else if (((hh2 >> i) & 1) != 0)
        {
            u_printf( " (%s)", name);
        }
    }
}

//----------------------------------------------------------------------------
static int choose_hash(unsigned hh)
{
    static const int f[] =
    {
        br_sha256_ID, br_sha224_ID, br_sha384_ID, br_sha512_ID,
        br_sha1_ID, br_md5sha1_ID, -1
    };

    size_t u;

    for (u = 0; f[u] >= 0; u ++)
    {
        if (((hh >> f[u]) & 1) != 0)
        {
            return f[u];
        }
    }
    return -1;
}

//----------------------------------------------------------------------------
static void cc_choose(const br_ssl_client_certificate_class ** pctx,
                      const br_ssl_client_context * cc,
                      uint32_t auth_types,
                      br_ssl_client_certificate * choices)
{
    ccert_context *zc;
    int scurve;

    zc = (ccert_context *)pctx;
    scurve = br_ssl_client_get_server_curve(cc);
    if (zc->verbose)
    {
        unsigned hashes;

        hashes = br_ssl_client_get_server_hashes(cc);
        if((auth_types & 0x00FF) != 0)
        {
            u_printf( "supported: RSA signatures:");
            print_hashes(auth_types, hashes);
            u_printf( "\n");
        }
        if((auth_types & 0xFF00) != 0)
        {
            u_printf( "supported: ECDSA signatures:");
            print_hashes(auth_types >> 8, hashes >> 8);
            u_printf( "\n");
        }
        if((auth_types & 0x010000) != 0)
        {
            u_printf( "supported:"
                      " fixed ECDH (cert signed with RSA)\n");
        }
        if((auth_types & 0x020000) != 0)
        {
            u_printf( "supported:"
                      " fixed ECDH (cert signed with ECDSA)\n");
        }
        if(scurve)
        {
            u_printf( "server key curve: %s (%d)\n",
                      ec_curve_name(scurve), scurve);
        }
        else
        {
            u_printf( "server key is not EC\n");
        }
    }
    switch(zc->sk->key_type)
    {
        case BR_KEYTYPE_RSA:
            if((choices->hash_id = choose_hash(auth_types)) >= 0)
            {
                if(zc->verbose)
                {
                    u_printf( "using RSA, hash = %d (%s)\n",
                              choices->hash_id,
                              hash_function_name(choices->hash_id));
                }
                choices->auth_type = BR_AUTH_RSA;
                choices->chain = zc->chain;
                choices->chain_len = zc->chain_len;
                return;
            }
            break;
        case BR_KEYTYPE_EC:
            if(zc->issuer_key_type != 0
                    && scurve == zc->sk->key.ec.curve)
            {
                int x;

                x = (zc->issuer_key_type == BR_KEYTYPE_RSA) ? 16 : 17;
                if(((auth_types >> x) & 1) != 0)
                {
                    if(zc->verbose)
                    {
                        u_printf( "using static ECDH\n");
                    }
                    choices->auth_type = BR_AUTH_ECDH;
                    choices->hash_id = -1;
                    choices->chain = zc->chain;
                    choices->chain_len = zc->chain_len;
                    return;
                }
            }
            if((choices->hash_id = choose_hash(auth_types >> 8)) >= 0)
            {
                if(zc->verbose)
                {
                    u_printf( "using ECDSA, hash = %d (%s)\n",
                              choices->hash_id,
                              hash_function_name(choices->hash_id));
                }
                choices->auth_type = BR_AUTH_ECDSA;
                choices->chain = zc->chain;
                choices->chain_len = zc->chain_len;
                return;
            }
            break;
    }
    if(zc->verbose)
    {
        u_printf( "no matching client certificate\n");
    }
    choices->chain = NULL;
    choices->chain_len = 0;
}

//----------------------------------------------------------------------------
static uint32_t cc_do_keyx(const br_ssl_client_certificate_class ** pctx,
                           unsigned char * data,
                           size_t * len)
{
    const br_ec_impl *iec;
    ccert_context *zc;
    size_t xoff, xlen;
    uint32_t r;

    zc = (ccert_context *)pctx;
    iec = br_ec_get_default();
    r = iec->mul(data,
                 *len,
                 zc->sk->key.ec.x,
                 zc->sk->key.ec.xlen,
                 zc->sk->key.ec.curve);
    xoff = iec->xoff(zc->sk->key.ec.curve, &xlen);
    memmove(data, data + xoff, xlen);
    *len = xlen;
    return r;
}

//----------------------------------------------------------------------------
static size_t cc_do_sign(const br_ssl_client_certificate_class ** pctx,
                         int hash_id,
                         size_t hv_len,
                         unsigned char * data,
                         size_t len)
{
    ccert_context *zc;
    unsigned char hv[64];

    zc = (ccert_context *)pctx;
    memcpy(hv, data, hv_len);
    switch (zc->sk->key_type)
    {
            const br_hash_class *hc;
            const unsigned char *hash_oid;
            uint32_t x;
            size_t sig_len;

        case BR_KEYTYPE_RSA:
            hash_oid = get_hash_oid(hash_id);
            if(hash_oid == NULL && hash_id != 0)
            {
                if(zc->verbose)
                {
                    u_printf( "ERROR: cannot RSA-sign with"
                              " unknown hash function: %d\n",
                              hash_id);
                }
                return 0;
            }
            sig_len = (zc->sk->key.rsa.n_bitlen + 7) >> 3;
            if(len < sig_len)
            {
                if(zc->verbose)
                {
                    u_printf( "ERROR: cannot RSA-sign,"
                              " buffer is too small"
                              " (sig=%lu, buf=%lu)\n",
                              (unsigned long)sig_len,
                              (unsigned long)len);
                }
                return 0;
            }
            x = br_rsa_pkcs1_sign_get_default()(
                    hash_oid, hv, hv_len, &zc->sk->key.rsa, data);
            if(!x)
            {
                if(zc->verbose)
                {
                    u_printf( "ERROR: RSA-sign failure\n");
                }
                return 0;
            }
            return sig_len;

        case BR_KEYTYPE_EC:
            hc = get_hash_impl(hash_id);
            if(hc == NULL)
            {
                if(zc->verbose)
                {
                    u_printf( "ERROR: cannot ECDSA-sign with"
                              " unknown hash function: %d\n",
                              hash_id);
                }
                return 0;
            }
            if(len < 139)
            {
                if(zc->verbose)
                {
                    u_printf( "ERROR: cannot ECDSA-sign"
                              " (output buffer = %lu)\n",
                              (unsigned long)len);
                }
                return 0;
            }
            sig_len = br_ecdsa_sign_asn1_get_default()(
                          br_ec_get_default(), hc, hv, &zc->sk->key.ec, data);
            if(sig_len == 0)
            {
                if(zc->verbose)
                {
                    u_printf( "ERROR: ECDSA-sign failure\n");
                }
                return 0;
            }
            return sig_len;

        default:
            return 0;
    }
}

//----------------------------------------------------------------------------
//----------------------------------------------------------------------------
//----------------------------------------------------------------------------

static const br_ssl_client_certificate_class ccert_vtable =
{
    sizeof(ccert_context),
    cc_start_name_list,
    cc_start_name,
    cc_append_name,
    cc_end_name,
    cc_end_name_list,
    cc_choose,
    cc_do_keyx,
    cc_do_sign
};

//----------------------------------------------------------------------------
int do_client_init(BEARSSL_SSL * ssl,
                   char * server_name_a, // name:port i.e '127.0.0.1:8883'
                   int verbose_a,
                   char * sni_a,
                   char * ca_name,
                   char * cert_name,
                   char * key_name,
                   int fd)  // Socket fd
{
    int retcode;
    int verbose;
    int bidi;

#if 0
    const char *server_name;
    char *host;
    char *port;
    const char *sni;
#endif

    size_t u;

    retcode = 0;
    //verbose = ;
//    trace = 0;
    ssl->server_name = NULL;
    ssl->host = NULL;
    ssl->port = NULL;
    ssl->sni = NULL;

    bidi = 1;

    memset(&ssl->anchors, 0, sizeof(ssl->anchors));
    memset(&ssl->alpn_names, 0, sizeof(ssl->anchors));
    ssl->vmin = 0;
    ssl->vmax = 0;
    ssl->suites = NULL;
    ssl->num_suites = 0;
    ssl->hfuns = 0;
    ssl->suite_ids = NULL;
    ssl->chain = NULL;
    ssl->chain_len = 0;
    ssl->sk = NULL;
    ssl->nostaticecdh = 0;
    ssl->iobuf = NULL;
    ssl->iobuf_len = 0;
    ssl->minhello_len = (size_t)-1;
    ssl->fallback = 0;
    ssl->flags = 0;
   // fd = INVALID_SOCKET;

    ssl->server_name = server_name_a;
    verbose = verbose_a;
//  trace = 1;
    ssl->sni = sni_a;

    if(read_trust_anchors(&ssl->anchors, ca_name) == 0)
    {
        goto client_exit_error;
    }

    ssl->chain = read_certificates(cert_name, &ssl->chain_len);
    if(ssl->chain == NULL || ssl->chain_len == 0)
    {
       goto client_exit_error;
    }

    ssl->sk = read_private_key(key_name);
    if(ssl->sk == NULL)
    {
        goto client_exit_error;
    }

    if(ssl->server_name == NULL)
    {
        u_printf( "ERROR: no server name/address provided\n");
        goto client_exit_error;
    }

    for(u = strlen(ssl->server_name); u > 0; u --)
    {
        int c = ssl->server_name[u - 1];
        if (c == ':')
        {
            break;
        }
        if (c < '0' || c > '9')
        {
            u = 0;
            break;
        }
    }

    if(u == 0)
    {
        ssl->host = xstrdup(ssl->server_name);
        ssl->port = xstrdup("443");
    }
    else
    {
        ssl->port = xstrdup(ssl->server_name + u);
        ssl->host = xmalloc(u);
        memcpy(ssl->host, ssl->server_name, u - 1);
        ssl->host[u - 1] = 0;
    }

    if(ssl->sni == NULL)
    {
        ssl->sni = ssl->host;
    }

    if(ssl->chain == NULL && ssl->sk != NULL)
    {
        u_printf( "ERROR: private key specified, but"
                " no certificate chain\n");
        goto client_exit_error;
    }
    if(ssl->chain != NULL && ssl->sk == NULL)
    {
        u_printf( "ERROR: certificate chain specified, but"
                " no private key\n");
        goto client_exit_error;
    }

    if(ssl->vmin == 0)
    {
        ssl->vmin = BR_TLS12; //BR_TLS10;
    }
    if(ssl->vmax == 0)
    {
        ssl->vmax = BR_TLS12;
    }

    if(ssl->vmax < ssl->vmin)
    {
        u_printf( "ERROR: impossible minimum/maximum protocol"
                " version combination\n");
        goto client_exit_error;
    }

    if(ssl->hfuns == 0)
    {
        ssl->hfuns = (unsigned int)-1;
    }

    if(ssl->iobuf_len == 0)
    {
        if(bidi)
        {
            ssl->iobuf_len = BR_SSL_BUFSIZE_BIDI;
        }
        else
        {
            ssl->iobuf_len = BR_SSL_BUFSIZE_MONO;
        }
    }

    u_printf( "BearSSL iobuf size - %u\n", ssl->iobuf_len);
    ssl->iobuf = xmalloc(ssl->iobuf_len);

    /*
     * Compute implementation requirements and inject implementations.
     */

  //  ssl->suite_ids = xmalloc((ssl->num_suites + 1) * sizeof *ssl->suite_ids);

    br_ssl_client_zero(&ssl->cc);
    br_ssl_engine_set_versions(&ssl->cc.eng, ssl->vmin, ssl->vmax);

    ssl->dnhash = NULL;
    for (u = 0; hash_functions[u].name; u ++)
    {
        const br_hash_class *hc;
        int id;

        hc = hash_functions[u].hclass;
        id = (hc->desc >> BR_HASHDESC_ID_OFF) & BR_HASHDESC_ID_MASK;
        if ((ssl->hfuns & ((unsigned)1 << id)) != 0)
        {
            ssl->dnhash = hc;
        }
    }
    if (ssl->dnhash == NULL)
    {
        u_printf( "ERROR: no supported hash function\n");
        goto client_exit_error;
    }

    br_x509_minimal_init(&ssl->xc, ssl->dnhash,
                         &VEC_ELT(ssl->anchors, 0),
                         VEC_LEN(ssl->anchors));

    if(ssl->vmin <= BR_TLS11)
    {
        if (!(ssl->hfuns & (1 << br_md5_ID)))
        {
            u_printf( "ERROR: TLS 1.0 and 1.1 need MD5\n");
            goto client_exit_error;
        }
        if (!(ssl->hfuns & (1 << br_sha1_ID)))
        {
            u_printf( "ERROR: TLS 1.0 and 1.1 need SHA-1\n");
            goto client_exit_error;
        }
    }

    if(ssl->fallback)
    {
        ssl->suite_ids[ssl->num_suites ++] = 0x5600;
    }

// origin
//    br_ssl_engine_set_suites(&ssl->cc.eng, ssl->suite_ids, ssl->num_suites);

    ssl->suite_ids = (uint16_t*)&g_suites[0];
    ssl->num_suites = (sizeof g_suites) / (sizeof g_suites[0]);

    br_ssl_engine_set_default_aes_cbc(&ssl->cc.eng);
    br_ssl_engine_set_default_aes_ccm(&ssl->cc.eng);
    br_ssl_engine_set_default_aes_gcm(&ssl->cc.eng);
    br_ssl_engine_set_default_chapol(&ssl->cc.eng);
    br_ssl_engine_set_default_des_cbc(&ssl->cc.eng);
    br_ssl_client_set_default_rsapub(&ssl->cc);
    br_ssl_engine_set_default_ec(&ssl->cc.eng);
    br_ssl_engine_set_default_rsavrfy(&ssl->cc.eng);
    br_ssl_engine_set_default_ecdsa(&ssl->cc.eng);
    br_ssl_engine_set_default_ec(&ssl->cc.eng);

    br_ssl_engine_set_suites(&ssl->cc.eng, ssl->suite_ids, ssl->num_suites);

//-----------------------
    for(int id = br_md5_ID; id <= br_sha512_ID; id ++)
    {
        const br_hash_class *hc;

        hc = g_hashes[id - 1];

        br_ssl_engine_set_hash(&ssl->cc.eng, id, hc);
        br_x509_minimal_set_hash(&ssl->xc, id, hc);
    }
//-----------------------

    if (ssl->vmin <= BR_TLS11)
    {
        br_ssl_engine_set_prf10(&ssl->cc.eng, &br_tls10_prf);
    }

    if (ssl->vmax >= BR_TLS12)
    {
        if ((ssl->hfuns & ((unsigned)1 << br_sha256_ID)) != 0)
        {
            br_ssl_engine_set_prf_sha256(&ssl->cc.eng,
                                         &br_tls12_sha256_prf);
        }
        if ((ssl->hfuns & ((unsigned)1 << br_sha384_ID)) != 0)
        {
            br_ssl_engine_set_prf_sha384(&ssl->cc.eng,
                                         &br_tls12_sha384_prf);
        }
    }

    br_x509_minimal_set_rsa(&ssl->xc, br_rsa_pkcs1_vrfy_get_default());
    br_x509_minimal_set_ecdsa(&ssl->xc,
                              br_ec_get_default(), br_ecdsa_vrfy_asn1_get_default());

    /*
     * If there is no provided trust anchor, then certificate validation
     * will always fail. In that situation, we use our custom wrapper
     * that tolerates unknown anchors.
     */
    if (VEC_LEN(ssl->anchors) == 0)
    {
        if (verbose)
        {
            u_printf("WARNING: no configured trust anchor\n");
        }
        x509_noanchor_init(&ssl->xwc, &ssl->xc.vtable);
        br_ssl_engine_set_x509(&ssl->cc.eng, &ssl->xwc.vtable);
    }
    else
    {
        br_ssl_engine_set_x509(&ssl->cc.eng, &ssl->xc.vtable);
    }

    if (ssl->minhello_len != (size_t)-1)
    {
        br_ssl_client_set_min_clienthello_len(&ssl->cc, ssl->minhello_len);
    }

    br_ssl_engine_set_all_flags(&ssl->cc.eng, ssl->flags);

    if (VEC_LEN(ssl->alpn_names) != 0)
    {
        br_ssl_engine_set_protocol_names(&ssl->cc.eng,
                                         (const char **)&VEC_ELT(ssl->alpn_names, 0),
                                         VEC_LEN(ssl->alpn_names));
    }

    if (ssl->chain != NULL)
    {
        ssl->zc.vtable = &ccert_vtable;
        ssl->zc.verbose = verbose;
        ssl->zc.chain = ssl->chain;
        ssl->zc.chain_len = ssl->chain_len;
        ssl->zc.sk = ssl->sk;
        if (ssl->nostaticecdh || ssl->sk->key_type != BR_KEYTYPE_EC)
        {
            ssl->zc.issuer_key_type = 0;
        }
        else
        {
            ssl->zc.issuer_key_type = get_cert_signer_algo(&ssl->chain[0]);
            if (ssl->zc.issuer_key_type == 0)
            {
                goto client_exit_error;
            }
        }
        br_ssl_client_set_client_certificate(&ssl->cc, &ssl->zc.vtable);
    }

    br_ssl_engine_set_buffer(&ssl->cc.eng, ssl->iobuf, ssl->iobuf_len, bidi);

    //u_printf("===sni===: %s %p sni[0]: %d \n", ssl->sni, ssl->sni, ssl->sni[0]);  // YVT

    br_ssl_client_reset(&ssl->cc, ssl->sni, 0);

//----

    return 0;

client_exit:

    xfree(ssl->host);
    xfree(ssl->port);
    xfree(ssl->suites);
//    xfree(ssl->suite_ids);
    VEC_CLEAREXT(ssl->anchors, &free_ta_contents);
 //   VEC_CLEAREXT(ssl->alpn_names, &free_alpn);
    free_certificates(ssl->chain, ssl->chain_len);
    free_private_key(ssl->sk);
    xfree(ssl->iobuf);
    //if (fd != INVALID_SOCKET)
    //{
    //    close(fd);
    //}
    return retcode;

client_exit_error:

    retcode = -1;
    goto client_exit;
}

//===================================================================

