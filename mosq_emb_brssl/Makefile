# =============================================================================
#
# Makefile for 'mosq_emb_brssl' project
#
# Author: Yuri Tiomkin
#
# =============================================================================


# =========  Pathes ==============

ROOTPATH = /home/yurit/Projects/mosquitto_emb

PRJROOTPATH   = $(ROOTPATH)/mosq_emb_brssl
BEARSSL_PATH  = $(ROOTPATH)/mosq_emb_brssl/BearSSL
BEARSSL_PATH_TOOLS = $(BEARSSL_PATH)/tools
BEARSSL_PATH_SRC = $(BEARSSL_PATH)/src
BEARSSL_PATH_AEAD = $(BEARSSL_PATH_SRC)/aead
BEARSSL_PATH_CODEC = $(BEARSSL_PATH_SRC)/codec
BEARSSL_PATH_EC = $(BEARSSL_PATH_SRC)/ec
BEARSSL_PATH_HASH = $(BEARSSL_PATH_SRC)/hash
BEARSSL_PATH_INT = $(BEARSSL_PATH_SRC)/int
BEARSSL_PATH_KDF = $(BEARSSL_PATH_SRC)/kdf
BEARSSL_PATH_MAC = $(BEARSSL_PATH_SRC)/mac
BEARSSL_PATH_RAND = $(BEARSSL_PATH_SRC)/rand
BEARSSL_PATH_RSA = $(BEARSSL_PATH_SRC)/rsa
BEARSSL_PATH_SSL = $(BEARSSL_PATH_SRC)/ssl
BEARSSL_PATH_SYMCIPHER = $(BEARSSL_PATH_SRC)/symcipher
BEARSSL_PATH_X509 = $(BEARSSL_PATH_SRC)/x509
MOSQUITTO_PATH = $(PRJROOTPATH)/mosq_emb_client

INCLUDES = -I ./ -IBearSSL/src -IBearSSL/inc -IBearSSL/tools -Imosq_emb_client -I../mosq_emb_brssl

OBJ_DIR = $(PRJROOTPATH)/obj

VPATH = $(PRJROOTPATH) $(BEARSSL_PATH) $(BEARSSL_PATH_SRC) $(BEARSSL_PATH_AEAD)\
  $(BEARSSL_PATH_CODEC) $(BEARSSL_PATH_EC) $(BEARSSL_PATH_HASH) $(BEARSSL_PATH_INT)\
  $(BEARSSL_PATH_KDF) $(BEARSSL_PATH_MAC) $(BEARSSL_PATH_RAND) $(BEARSSL_PATH_RSA)\
  $(BEARSSL_PATH_SSL) $(BEARSSL_PATH_SYMCIPHER) $(BEARSSL_PATH_X509)\
  $(BEARSSL_PATH_TOOLS) $(MOSQUITTO_PATH)

#===========  Files  ==============

#--  Project target file name (without extension).

IMAGE = mosq_emb_brssl

#-- List of objects


OBJECTS = \
    $(OBJ_DIR)/ccm.o\
	$(OBJ_DIR)/eax.o \
	$(OBJ_DIR)/gcm.o \
	$(OBJ_DIR)/ccopy.o \
	$(OBJ_DIR)/dec16be.o \
	$(OBJ_DIR)/dec16le.o \
	$(OBJ_DIR)/dec32be.o \
	$(OBJ_DIR)/dec32le.o \
	$(OBJ_DIR)/dec64be.o \
	$(OBJ_DIR)/dec64le.o \
	$(OBJ_DIR)/enc16be.o \
	$(OBJ_DIR)/enc16le.o \
	$(OBJ_DIR)/enc32be.o \
	$(OBJ_DIR)/enc32le.o \
	$(OBJ_DIR)/enc64be.o \
	$(OBJ_DIR)/enc64le.o \
	$(OBJ_DIR)/pemdec.o \
	$(OBJ_DIR)/pemenc.o \
	$(OBJ_DIR)/ec_all_m15.o \
	$(OBJ_DIR)/ec_all_m31.o \
	$(OBJ_DIR)/ec_c25519_i15.o \
	$(OBJ_DIR)/ec_c25519_i31.o \
	$(OBJ_DIR)/ec_c25519_m15.o \
	$(OBJ_DIR)/ec_c25519_m31.o \
	$(OBJ_DIR)/ec_c25519_m62.o \
	$(OBJ_DIR)/ec_c25519_m64.o \
	$(OBJ_DIR)/ec_curve25519.o \
	$(OBJ_DIR)/ec_default.o \
	$(OBJ_DIR)/ec_keygen.o \
	$(OBJ_DIR)/ec_p256_m15.o \
	$(OBJ_DIR)/ec_p256_m31.o \
	$(OBJ_DIR)/ec_p256_m62.o \
	$(OBJ_DIR)/ec_p256_m64.o \
	$(OBJ_DIR)/ec_prime_i15.o \
	$(OBJ_DIR)/ec_prime_i31.o \
	$(OBJ_DIR)/ec_pubkey.o \
	$(OBJ_DIR)/ec_secp256r1.o \
	$(OBJ_DIR)/ec_secp384r1.o \
	$(OBJ_DIR)/ec_secp521r1.o \
	$(OBJ_DIR)/ecdsa_atr.o \
	$(OBJ_DIR)/ecdsa_default_sign_asn1.o \
	$(OBJ_DIR)/ecdsa_default_sign_raw.o \
	$(OBJ_DIR)/ecdsa_default_vrfy_asn1.o \
	$(OBJ_DIR)/ecdsa_default_vrfy_raw.o \
	$(OBJ_DIR)/ecdsa_i15_bits.o \
	$(OBJ_DIR)/ecdsa_i15_sign_asn1.o \
	$(OBJ_DIR)/ecdsa_i15_sign_raw.o \
	$(OBJ_DIR)/ecdsa_i15_vrfy_asn1.o \
	$(OBJ_DIR)/ecdsa_i15_vrfy_raw.o \
	$(OBJ_DIR)/ecdsa_i31_bits.o \
	$(OBJ_DIR)/ecdsa_i31_sign_asn1.o \
	$(OBJ_DIR)/ecdsa_i31_sign_raw.o \
	$(OBJ_DIR)/ecdsa_i31_vrfy_asn1.o \
	$(OBJ_DIR)/ecdsa_i31_vrfy_raw.o \
	$(OBJ_DIR)/ecdsa_rta.o \
	$(OBJ_DIR)/dig_oid.o \
	$(OBJ_DIR)/dig_size.o \
	$(OBJ_DIR)/ghash_ctmul.o \
	$(OBJ_DIR)/ghash_ctmul32.o \
	$(OBJ_DIR)/ghash_ctmul64.o \
	$(OBJ_DIR)/ghash_pclmul.o \
	$(OBJ_DIR)/ghash_pwr8.o \
	$(OBJ_DIR)/md5.o \
	$(OBJ_DIR)/md5sha1.o \
	$(OBJ_DIR)/mgf1.o \
	$(OBJ_DIR)/multihash.o \
	$(OBJ_DIR)/sha1.o \
	$(OBJ_DIR)/sha2big.o \
	$(OBJ_DIR)/sha2small.o \
	$(OBJ_DIR)/i15_add.o \
	$(OBJ_DIR)/i15_bitlen.o \
	$(OBJ_DIR)/i15_decmod.o \
	$(OBJ_DIR)/i15_decode.o \
	$(OBJ_DIR)/i15_decred.o \
	$(OBJ_DIR)/i15_encode.o \
	$(OBJ_DIR)/i15_fmont.o \
	$(OBJ_DIR)/i15_iszero.o \
	$(OBJ_DIR)/i15_moddiv.o \
	$(OBJ_DIR)/i15_modpow.o \
	$(OBJ_DIR)/i15_modpow2.o \
	$(OBJ_DIR)/i15_montmul.o \
	$(OBJ_DIR)/i15_mulacc.o \
	$(OBJ_DIR)/i15_muladd.o \
	$(OBJ_DIR)/i15_ninv15.o \
	$(OBJ_DIR)/i15_reduce.o \
	$(OBJ_DIR)/i15_rshift.o \
	$(OBJ_DIR)/i15_sub.o \
	$(OBJ_DIR)/i15_tmont.o \
	$(OBJ_DIR)/i31_add.o \
	$(OBJ_DIR)/i31_bitlen.o \
	$(OBJ_DIR)/i31_decmod.o \
	$(OBJ_DIR)/i31_decode.o \
	$(OBJ_DIR)/i31_decred.o \
	$(OBJ_DIR)/i31_encode.o \
	$(OBJ_DIR)/i31_fmont.o \
	$(OBJ_DIR)/i31_iszero.o \
	$(OBJ_DIR)/i31_moddiv.o \
	$(OBJ_DIR)/i31_modpow.o \
	$(OBJ_DIR)/i31_modpow2.o \
	$(OBJ_DIR)/i31_montmul.o \
	$(OBJ_DIR)/i31_mulacc.o \
	$(OBJ_DIR)/i31_muladd.o \
	$(OBJ_DIR)/i31_ninv31.o \
	$(OBJ_DIR)/i31_reduce.o \
	$(OBJ_DIR)/i31_rshift.o \
	$(OBJ_DIR)/i31_sub.o \
	$(OBJ_DIR)/i31_tmont.o \
	$(OBJ_DIR)/i32_add.o \
	$(OBJ_DIR)/i32_bitlen.o \
	$(OBJ_DIR)/i32_decmod.o \
	$(OBJ_DIR)/i32_decode.o \
	$(OBJ_DIR)/i32_decred.o \
	$(OBJ_DIR)/i32_div32.o \
	$(OBJ_DIR)/i32_encode.o \
	$(OBJ_DIR)/i32_fmont.o \
	$(OBJ_DIR)/i32_iszero.o \
	$(OBJ_DIR)/i32_modpow.o \
	$(OBJ_DIR)/i32_montmul.o \
	$(OBJ_DIR)/i32_mulacc.o \
	$(OBJ_DIR)/i32_muladd.o \
	$(OBJ_DIR)/i32_ninv32.o \
	$(OBJ_DIR)/i32_reduce.o \
	$(OBJ_DIR)/i32_sub.o \
	$(OBJ_DIR)/i32_tmont.o \
	$(OBJ_DIR)/i62_modpow2.o \
	$(OBJ_DIR)/hkdf.o \
	$(OBJ_DIR)/shake.o \
	$(OBJ_DIR)/hmac.o \
	$(OBJ_DIR)/hmac_ct.o \
	$(OBJ_DIR)/aesctr_drbg.o \
	$(OBJ_DIR)/hmac_drbg.o \
	$(OBJ_DIR)/sysrng.o \
	$(OBJ_DIR)/rsa_default_keygen.o \
	$(OBJ_DIR)/rsa_default_modulus.o \
	$(OBJ_DIR)/rsa_default_oaep_decrypt.o \
	$(OBJ_DIR)/rsa_default_oaep_encrypt.o \
	$(OBJ_DIR)/rsa_default_pkcs1_sign.o \
	$(OBJ_DIR)/rsa_default_pkcs1_vrfy.o \
	$(OBJ_DIR)/rsa_default_priv.o \
	$(OBJ_DIR)/rsa_default_privexp.o \
	$(OBJ_DIR)/rsa_default_pss_sign.o \
	$(OBJ_DIR)/rsa_default_pss_vrfy.o \
	$(OBJ_DIR)/rsa_default_pub.o \
	$(OBJ_DIR)/rsa_default_pubexp.o \
	$(OBJ_DIR)/rsa_i15_keygen.o \
	$(OBJ_DIR)/rsa_i15_modulus.o \
	$(OBJ_DIR)/rsa_i15_oaep_decrypt.o \
	$(OBJ_DIR)/rsa_i15_oaep_encrypt.o \
	$(OBJ_DIR)/rsa_i15_pkcs1_sign.o \
	$(OBJ_DIR)/rsa_i15_pkcs1_vrfy.o \
	$(OBJ_DIR)/rsa_i15_priv.o \
	$(OBJ_DIR)/rsa_i15_privexp.o \
	$(OBJ_DIR)/rsa_i15_pss_sign.o \
	$(OBJ_DIR)/rsa_i15_pss_vrfy.o \
	$(OBJ_DIR)/rsa_i15_pub.o \
	$(OBJ_DIR)/rsa_i15_pubexp.o \
	$(OBJ_DIR)/rsa_i31_keygen.o \
	$(OBJ_DIR)/rsa_i31_keygen_inner.o \
	$(OBJ_DIR)/rsa_i31_modulus.o \
	$(OBJ_DIR)/rsa_i31_oaep_decrypt.o \
	$(OBJ_DIR)/rsa_i31_oaep_encrypt.o \
	$(OBJ_DIR)/rsa_i31_pkcs1_sign.o \
	$(OBJ_DIR)/rsa_i31_pkcs1_vrfy.o \
	$(OBJ_DIR)/rsa_i31_priv.o \
	$(OBJ_DIR)/rsa_i31_privexp.o \
	$(OBJ_DIR)/rsa_i31_pss_sign.o \
	$(OBJ_DIR)/rsa_i31_pss_vrfy.o \
	$(OBJ_DIR)/rsa_i31_pub.o \
	$(OBJ_DIR)/rsa_i31_pubexp.o \
	$(OBJ_DIR)/rsa_i32_oaep_decrypt.o \
	$(OBJ_DIR)/rsa_i32_oaep_encrypt.o \
	$(OBJ_DIR)/rsa_i32_pkcs1_sign.o \
	$(OBJ_DIR)/rsa_i32_pkcs1_vrfy.o \
	$(OBJ_DIR)/rsa_i32_priv.o \
	$(OBJ_DIR)/rsa_i32_pss_sign.o \
	$(OBJ_DIR)/rsa_i32_pss_vrfy.o \
	$(OBJ_DIR)/rsa_i32_pub.o \
	$(OBJ_DIR)/rsa_i62_keygen.o \
	$(OBJ_DIR)/rsa_i62_oaep_decrypt.o \
	$(OBJ_DIR)/rsa_i62_oaep_encrypt.o \
	$(OBJ_DIR)/rsa_i62_pkcs1_sign.o \
	$(OBJ_DIR)/rsa_i62_pkcs1_vrfy.o \
	$(OBJ_DIR)/rsa_i62_priv.o \
	$(OBJ_DIR)/rsa_i62_pss_sign.o \
	$(OBJ_DIR)/rsa_i62_pss_vrfy.o \
	$(OBJ_DIR)/rsa_i62_pub.o \
	$(OBJ_DIR)/rsa_oaep_pad.o \
	$(OBJ_DIR)/rsa_oaep_unpad.o \
	$(OBJ_DIR)/rsa_pkcs1_sig_pad.o \
	$(OBJ_DIR)/rsa_pkcs1_sig_unpad.o \
	$(OBJ_DIR)/rsa_pss_sig_pad.o \
	$(OBJ_DIR)/rsa_pss_sig_unpad.o \
	$(OBJ_DIR)/rsa_ssl_decrypt.o \
	$(OBJ_DIR)/settings.o \
	$(OBJ_DIR)/prf.o \
	$(OBJ_DIR)/prf_md5sha1.o \
	$(OBJ_DIR)/prf_sha256.o \
	$(OBJ_DIR)/prf_sha384.o \
	$(OBJ_DIR)/ssl_ccert_single_ec.o \
	$(OBJ_DIR)/ssl_ccert_single_rsa.o \
	$(OBJ_DIR)/ssl_client.o \
	$(OBJ_DIR)/ssl_client_default_rsapub.o \
	$(OBJ_DIR)/ssl_client_full.o \
	$(OBJ_DIR)/ssl_engine.o \
	$(OBJ_DIR)/ssl_engine_default_aescbc.o \
	$(OBJ_DIR)/ssl_engine_default_aesccm.o \
	$(OBJ_DIR)/ssl_engine_default_aesgcm.o \
	$(OBJ_DIR)/ssl_engine_default_chapol.o \
	$(OBJ_DIR)/ssl_engine_default_descbc.o \
	$(OBJ_DIR)/ssl_engine_default_ec.o \
	$(OBJ_DIR)/ssl_engine_default_ecdsa.o \
	$(OBJ_DIR)/ssl_engine_default_rsavrfy.o \
	$(OBJ_DIR)/ssl_hashes.o \
	$(OBJ_DIR)/ssl_hs_client.o \
	$(OBJ_DIR)/ssl_hs_server.o \
	$(OBJ_DIR)/ssl_io.o \
	$(OBJ_DIR)/ssl_keyexport.o \
	$(OBJ_DIR)/ssl_lru.o \
	$(OBJ_DIR)/ssl_rec_cbc.o \
	$(OBJ_DIR)/ssl_rec_ccm.o \
	$(OBJ_DIR)/ssl_rec_chapol.o \
	$(OBJ_DIR)/ssl_rec_gcm.o \
	$(OBJ_DIR)/ssl_scert_single_ec.o \
	$(OBJ_DIR)/ssl_scert_single_rsa.o \
	$(OBJ_DIR)/ssl_server.o \
	$(OBJ_DIR)/ssl_server_full_ec.o \
	$(OBJ_DIR)/ssl_server_full_rsa.o \
	$(OBJ_DIR)/ssl_server_mine2c.o \
	$(OBJ_DIR)/ssl_server_mine2g.o \
	$(OBJ_DIR)/ssl_server_minf2c.o \
	$(OBJ_DIR)/ssl_server_minf2g.o \
	$(OBJ_DIR)/ssl_server_minr2g.o \
	$(OBJ_DIR)/ssl_server_minu2g.o \
	$(OBJ_DIR)/ssl_server_minv2g.o \
	$(OBJ_DIR)/aes_big_cbcdec.o \
	$(OBJ_DIR)/aes_big_cbcenc.o \
	$(OBJ_DIR)/aes_big_ctr.o \
	$(OBJ_DIR)/aes_big_ctrcbc.o \
	$(OBJ_DIR)/aes_big_dec.o \
	$(OBJ_DIR)/aes_big_enc.o \
	$(OBJ_DIR)/aes_common.o \
	$(OBJ_DIR)/aes_ct.o \
	$(OBJ_DIR)/aes_ct64.o \
	$(OBJ_DIR)/aes_ct64_cbcdec.o \
	$(OBJ_DIR)/aes_ct64_cbcenc.o \
	$(OBJ_DIR)/aes_ct64_ctr.o \
	$(OBJ_DIR)/aes_ct64_ctrcbc.o \
	$(OBJ_DIR)/aes_ct64_dec.o \
	$(OBJ_DIR)/aes_ct64_enc.o \
	$(OBJ_DIR)/aes_ct_cbcdec.o \
	$(OBJ_DIR)/aes_ct_cbcenc.o \
	$(OBJ_DIR)/aes_ct_ctr.o \
	$(OBJ_DIR)/aes_ct_ctrcbc.o \
	$(OBJ_DIR)/aes_ct_dec.o \
	$(OBJ_DIR)/aes_ct_enc.o \
	$(OBJ_DIR)/aes_pwr8.o \
	$(OBJ_DIR)/aes_pwr8_cbcdec.o \
	$(OBJ_DIR)/aes_pwr8_cbcenc.o \
	$(OBJ_DIR)/aes_pwr8_ctr.o \
	$(OBJ_DIR)/aes_pwr8_ctrcbc.o \
	$(OBJ_DIR)/aes_small_cbcdec.o \
	$(OBJ_DIR)/aes_small_cbcenc.o \
	$(OBJ_DIR)/aes_small_ctr.o \
	$(OBJ_DIR)/aes_small_ctrcbc.o \
	$(OBJ_DIR)/aes_small_dec.o \
	$(OBJ_DIR)/aes_small_enc.o \
	$(OBJ_DIR)/aes_x86ni.o \
	$(OBJ_DIR)/aes_x86ni_cbcdec.o \
	$(OBJ_DIR)/aes_x86ni_cbcenc.o \
	$(OBJ_DIR)/aes_x86ni_ctr.o \
	$(OBJ_DIR)/aes_x86ni_ctrcbc.o \
	$(OBJ_DIR)/chacha20_ct.o \
	$(OBJ_DIR)/chacha20_sse2.o \
	$(OBJ_DIR)/des_ct.o \
	$(OBJ_DIR)/des_ct_cbcdec.o \
	$(OBJ_DIR)/des_ct_cbcenc.o \
	$(OBJ_DIR)/des_support.o \
	$(OBJ_DIR)/des_tab.o \
	$(OBJ_DIR)/des_tab_cbcdec.o \
	$(OBJ_DIR)/des_tab_cbcenc.o \
	$(OBJ_DIR)/poly1305_ctmul.o \
	$(OBJ_DIR)/poly1305_ctmul32.o \
	$(OBJ_DIR)/poly1305_ctmulq.o \
	$(OBJ_DIR)/poly1305_i15.o \
	$(OBJ_DIR)/asn1enc.o \
	$(OBJ_DIR)/encode_ec_pk8der.o \
	$(OBJ_DIR)/encode_ec_rawder.o \
	$(OBJ_DIR)/encode_rsa_pk8der.o \
	$(OBJ_DIR)/encode_rsa_rawder.o \
	$(OBJ_DIR)/skey_decoder.o \
	$(OBJ_DIR)/x509_decoder.o \
	$(OBJ_DIR)/x509_knownkey.o \
	$(OBJ_DIR)/x509_minimal.o \
	$(OBJ_DIR)/x509_minimal_full.o \
	$(OBJ_DIR)/certs.o \
	$(OBJ_DIR)/errors.o \
	$(OBJ_DIR)/files_ex.o \
	$(OBJ_DIR)/keys.o \
	$(OBJ_DIR)/names.o \
	$(OBJ_DIR)/vector.o \
	$(OBJ_DIR)/xmem.o  \
  $(OBJ_DIR)/logging_mosq.o\
  $(OBJ_DIR)/memory_mosq.o\
  $(OBJ_DIR)/messages_mosq.o\
  $(OBJ_DIR)/mosquitto_emb.o\
  $(OBJ_DIR)/net_mosq.o\
  $(OBJ_DIR)/read_handle.o\
  $(OBJ_DIR)/read_handle_client.o\
  $(OBJ_DIR)/read_handle_shared.o\
  $(OBJ_DIR)/send_client_mosq.o\
  $(OBJ_DIR)/send_mosq.o\
  $(OBJ_DIR)/time_mosq.o\
  $(OBJ_DIR)/util_mosq.o\
  $(OBJ_DIR)/will_mosq.o\
  $(OBJ_DIR)/buf_iov.o\
  $(OBJ_DIR)/mosq_brssl.o\
  $(OBJ_DIR)/mosq_brssl_main.o\
  $(OBJ_DIR)/mosq_emb_ex.o\
  $(OBJ_DIR)/tn_alloc.o

DEP_FILE =  $(OBJ_DIR)/$(notdir $(basename $@).d)

# create 'obj' directory, if not exists

SHELL := /bin/bash
REQUIRED_DIRS = $(OBJ_DIR)
_MKDIRS := $(shell for d in $(REQUIRED_DIRS); \
             do                               \
               [[ -d $$d ]] || mkdir -p $$d;  \
             done)

# ---------------------------------------------------------------------------
#  Tools, tools options(flags)
# ---------------------------------------------------------------------------

CC     = gcc
REMOVE  = rm
COPY    = copy
SIZE    = size

#-- Compiler(g++)  flags

CCOPTS  = $(INCLUDES) -m32 -Wall -fexceptions -Warray-bounds -O2 -c

#-- Linker flags

LDFLAGS = -s -m32 -lpthread

#-- Build & Linking ---

$(PRJPATH)/$(IMAGE): $(OBJECTS)
	$(CC) $(OBJECTS) $(LDFLAGS) --output $(OBJ_DIR)/$(notdir $@)

#--- Compiling

$(OBJ_DIR)/%.o:  %.c
	$(CC) $< $(CCOPTS) -MD -MF $(DEP_FILE) -o $@

# ===========================================================================

.PHONY:   clean
clean:

#$(REMOVE) -f $(LSTPATH)/*.lst
	   $(REMOVE) -f $(OBJ_DIR)/*.o
	   $(REMOVE) -f $(OBJ_DIR)/*.d

include  $(wildcard  $(OBJ_DIR)/$(notdir $(basename *.*).d))
