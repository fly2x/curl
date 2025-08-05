/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/

/*
 * Source file for all openHiTLS-specific code for the TLS/SSL layer. No code
 * but vtls.c should ever call or use these functions.
 */

#include "../curl_setup.h"

#ifdef USE_OPENHITLS

#include <tls/hitls.h>
#include <tls/hitls_config.h>
#include <tls/hitls_cert.h>
#include <tls/hitls_crypt_type.h>
#include <tls/hitls_error.h>
#include <tls/hitls_alpn.h>
#include <bsl/bsl_uio.h>
#include <bsl/bsl_err.h>
#include <crypto/crypt_eal_rand.h>
#include <pki/hitls_pki_x509.h>

#include "../urldata.h"
#include "../sendf.h"
#include "vtls.h"
#include "vtls_int.h"
#include "keylog.h"
#include "x509asn1.h"
#include "../strcase.h"
#include "../hostcheck.h"
#include "../curl_printf.h"
#include "../connect.h"
#include "../multiif.h"
#include "openhitls.h"

/* The last #include files should be: */
#include "../curl_memory.h"
#include "../memdebug.h"

struct openhitls_ssl_backend_data {
  struct openhitls_ctx openhitls;
};

static int openhitls_bio_cf_write(BSL_UIO *bio, const void *buf, size_t blen)
{
  struct Curl_cfilter *cf = (struct Curl_cfilter *)BSL_UIO_GetUserData(bio);
  struct ssl_connect_data *connssl = cf->ctx;
  struct Curl_easy *data = CF_DATA_CURRENT(cf);
  ssize_t nwritten;
  CURLcode result;

  DEBUGASSERT(data);
  nwritten = Curl_conn_cf_send(cf->next, data, (const char *)buf, blen, FALSE,
                               &result);
  if(nwritten < 0) {
    if(result == CURLE_AGAIN) {
      BSL_UIO_SetRetry(bio, BSL_UIO_RETRY_WRITE);
    }
    return -1;
  }
  return (int)nwritten;
}

static int openhitls_bio_cf_read(BSL_UIO *bio, void *buf, size_t blen)
{
  struct Curl_cfilter *cf = (struct Curl_cfilter *)BSL_UIO_GetUserData(bio);
  struct ssl_connect_data *connssl = cf->ctx;
  struct Curl_easy *data = CF_DATA_CURRENT(cf);
  ssize_t nread;
  CURLcode result;

  DEBUGASSERT(data);
  if(connssl->peer_closed) {
    return 0;
  }

  nread = Curl_conn_cf_recv(cf->next, data, (char *)buf, blen, &result);
  if(nread < 0) {
    if(result == CURLE_AGAIN) {
      BSL_UIO_SetRetry(bio, BSL_UIO_RETRY_READ);
    }
    return -1;
  }
  
  if(nread == 0) {
    connssl->peer_closed = TRUE;
  }

  return (int)nread;
}

static long openhitls_bio_cf_ctrl(BSL_UIO *bio, int cmd, long larg, void *parg)
{
  (void)bio;
  (void)larg;
  (void)parg;

  switch(cmd) {
  case BSL_UIO_CTRL_FLUSH:
    return 1;
  case BSL_UIO_CTRL_EOF:
    return 0;
  default:
    return 0;
  }
}

static BSL_UIO_Method *openhitls_bio_cf_method(void)
{
  static BSL_UIO_Method *method = NULL;

  if(!method) {
    method = BSL_UIO_NewMethod();
    if(!method)
      return NULL;

    BSL_UIO_SetMethodType(method, BSL_UIO_TYPE_FD);
    BSL_UIO_SetMethod(method, BSL_UIO_WRITE_CB, (void *)openhitls_bio_cf_write);
    BSL_UIO_SetMethod(method, BSL_UIO_READ_CB, (void *)openhitls_bio_cf_read);
    BSL_UIO_SetMethod(method, BSL_UIO_CTRL_CB, (void *)openhitls_bio_cf_ctrl);
  }

  return method;
}

/* Initialize openHiTLS */
static CURLcode openhitls_init(void)
{
  /* openHiTLS doesn't require global initialization */
  return CURLE_OK;
}

/* Cleanup openHiTLS */
static void openhitls_cleanup(void)
{
  /* openHiTLS doesn't require global cleanup */
}

static CURLcode openhitls_shutdown(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  bool send_shutdown, bool *done)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct openhitls_ssl_backend_data *backend = connssl->backend;
  struct openhitls_ctx *octx = &backend->openhitls;
  int32_t ret;

  DEBUGASSERT(backend);

  if(!octx->ctx || cf->shutdown) {
    *done = TRUE;
    return CURLE_OK;
  }

  if(data->set.ftp_ccc == CURLFTPSSL_CCC_ACTIVE && !connssl->peer_closed) {
    *done = TRUE;
    return CURLE_OK;
  }

  connssl->io_need = CURL_SSL_IO_NEED_NONE;
  
  if(send_shutdown && !connssl->peer_closed) {
    ret = HITLS_Close(octx->ctx);
    if(ret != HITLS_SUCCESS) {
      if(ret == HITLS_REC_NORMAL_RECV_BUF_EMPTY ||
         ret == HITLS_REC_NORMAL_IO_BUSY) {
        connssl->io_need = CURL_SSL_IO_NEED_RECV;
        *done = FALSE;
        return CURLE_OK;
      }
      /* Ignore other errors during shutdown */
    }
  }
  
  *done = TRUE;
  return CURLE_OK;
}

static void openhitls_close(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct openhitls_ssl_backend_data *backend = connssl->backend;
  struct openhitls_ctx *octx = &backend->openhitls;

  (void)data;
  DEBUGASSERT(backend);

  if(octx->ctx) {
    HITLS_Free(octx->ctx);
    octx->ctx = NULL;
  }

  if(octx->config) {
    HITLS_CFG_FreeConfig(octx->config);
    octx->config = NULL;
  }

  if(octx->bio) {
    BSL_UIO_Free(octx->bio);
    octx->bio = NULL;
  }

  if(octx->server_cert) {
    /* Note: openHiTLS may manage certificate memory internally */
    octx->server_cert = NULL;
  }

  if(octx->store_ctx) {
    HITLS_X509_StoreCtxFree(octx->store_ctx);
    octx->store_ctx = NULL;
  }
}

static CURLcode openhitls_connect_init(struct Curl_cfilter *cf,
                                      struct Curl_easy *data)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct openhitls_ssl_backend_data *backend = connssl->backend;
  struct openhitls_ctx *octx = &backend->openhitls;
  struct ssl_primary_config *conn_config = Curl_ssl_cf_get_primary_config(cf);
  struct ssl_config_data *ssl_config = Curl_ssl_cf_get_config(cf, data);
  HITLS_Config *config = NULL;
  HITLS_Ctx *ctx = NULL;
  BSL_UIO *bio = NULL;
  const char *ciphers;
  int ret;

  DEBUGASSERT(backend);

  /* Create config - use generic TLS config that supports all versions */
  config = HITLS_CFG_NewTLSConfig();
  if(!config) {
    failf(data, "Failed to create openHiTLS config");
    return CURLE_OUT_OF_MEMORY;
  }

  /* Set protocol versions */
  if(conn_config->version != CURL_SSLVERSION_DEFAULT) {
    uint16_t min_version = HITLS_VERSION_TLS10;
    uint16_t max_version = HITLS_VERSION_TLS13;
    
    switch(conn_config->version) {
    case CURL_SSLVERSION_TLSv1_0:
      min_version = HITLS_VERSION_TLS10;
      max_version = HITLS_VERSION_TLS10;
      break;
    case CURL_SSLVERSION_TLSv1_1:
      min_version = HITLS_VERSION_TLS11;
      max_version = HITLS_VERSION_TLS11;
      break;
    case CURL_SSLVERSION_TLSv1_2:
      min_version = HITLS_VERSION_TLS12;
      max_version = HITLS_VERSION_TLS12;
      break;
    case CURL_SSLVERSION_TLSv1_3:
      min_version = HITLS_VERSION_TLS13;
      max_version = HITLS_VERSION_TLS13;
      break;
    case CURL_SSLVERSION_MAX_TLSv1_0:
      min_version = HITLS_VERSION_TLS10;
      max_version = HITLS_VERSION_TLS10;
      break;
    case CURL_SSLVERSION_MAX_TLSv1_1:
      min_version = HITLS_VERSION_TLS10;
      max_version = HITLS_VERSION_TLS11;
      break;
    case CURL_SSLVERSION_MAX_TLSv1_2:
      min_version = HITLS_VERSION_TLS10;
      max_version = HITLS_VERSION_TLS12;
      break;
    case CURL_SSLVERSION_MAX_TLSv1_3:
      min_version = HITLS_VERSION_TLS10;
      max_version = HITLS_VERSION_TLS13;
      break;
    }
    
    ret = HITLS_CFG_SetVersion(config, min_version, max_version);
    if(ret != HITLS_SUCCESS) {
      failf(data, "Failed to set TLS versions");
      HITLS_CFG_FreeConfig(config);
      return CURLE_SSL_CONNECT_ERROR;
    }
  }

  /* Set cipher suites - note: this would need a proper cipher suite string parser */
  ciphers = conn_config->cipher_list;
  if(ciphers) {
    /* TODO: Parse cipher suite string and convert to uint16_t array */
    /* For now, we'll use default cipher suites */
    infof(data, "Custom cipher suites not yet implemented for openHiTLS");
  }

  /* Set verification mode */
  if(conn_config->verifypeer) {
    ret = HITLS_CFG_SetClientVerifySupport(config, true);
    if(ret != HITLS_SUCCESS) {
      failf(data, "Failed to set client verify support");
      HITLS_CFG_FreeConfig(config);
      return CURLE_SSL_CONNECT_ERROR;
    }
  } else {
    ret = HITLS_CFG_SetClientVerifySupport(config, false);
    if(ret != HITLS_SUCCESS) {
      failf(data, "Failed to set client verify support");
      HITLS_CFG_FreeConfig(config);
      return CURLE_SSL_CONNECT_ERROR;
    }
  }

  /* Set CA certificates */
  if(conn_config->CAfile || conn_config->CApath) {
    /* Create a certificate store context for CA verification */
    HITLS_X509_StoreCtx *store_ctx = HITLS_X509_StoreCtxNew();
    if(!store_ctx) {
      failf(data, "Failed to create certificate store context");
      HITLS_CFG_FreeConfig(config);
      return CURLE_OUT_OF_MEMORY;
    }

    /* Load CA certificates from file */
    if(conn_config->CAfile) {
      HITLS_TrustedCAList *ca_list = NULL;
      ret = HITLS_CFG_ParseCAList(config, conn_config->CAfile, 
                                  (uint32_t)strlen(conn_config->CAfile),
                                  HITLS_PARSE_TYPE_FILE,
                                  HITLS_PARSE_FORMAT_PEM,
                                  &ca_list);
      if(ret == HITLS_SUCCESS && ca_list) {
        ret = HITLS_CFG_SetCAList(config, ca_list);
        if(ret != HITLS_SUCCESS) {
          failf(data, "Failed to set CA list");
          HITLS_X509_StoreCtxFree(store_ctx);
          HITLS_CFG_FreeConfig(config);
          return CURLE_SSL_CACERT;
        }
      }
      else {
        failf(data, "Failed to parse CA file: %s", conn_config->CAfile);
        HITLS_X509_StoreCtxFree(store_ctx);
        HITLS_CFG_FreeConfig(config);
        return CURLE_SSL_CACERT_BADFILE;
      }
    }

    /* Load CA certificates from directory */
    if(conn_config->CApath) {
      /* Note: Directory-based CA loading may need additional implementation
         as openHiTLS may not directly support CApath like OpenSSL does */
      infof(data, "CA path loading not fully implemented for openHiTLS");
    }

    /* Set the store context for verification */
    ret = HITLS_CFG_SetVerifyStore(config, (HITLS_CERT_Store *)store_ctx, false);
    if(ret != HITLS_SUCCESS) {
      failf(data, "Failed to set verify store");
      HITLS_X509_StoreCtxFree(store_ctx);
      HITLS_CFG_FreeConfig(config);
      return CURLE_SSL_CONNECT_ERROR;
    }

    /* Set verification depth if configured */
    if(conn_config->verifyhost) {
      ret = HITLS_CFG_SetVerifyDepth(config, 9); /* Default depth */
      if(ret != HITLS_SUCCESS) {
        infof(data, "Failed to set verify depth");
      }
    }
    
    /* Save store context for later cleanup */
    octx->store_ctx = store_ctx;
  }

  /* Set client certificate if configured */
  if(conn_config->clientcert) {
    ret = HITLS_CFG_LoadCertFile(config, conn_config->clientcert, HITLS_PARSE_FORMAT_PEM);
    if(ret != HITLS_SUCCESS) {
      failf(data, "Failed to load client certificate: %s", conn_config->clientcert);
      HITLS_CFG_FreeConfig(config);
      return CURLE_SSL_CERTPROBLEM;
    }
  }

  /* Set client certificate from blob if configured */
  if(conn_config->cert_blob) {
    ret = HITLS_CFG_LoadCertBuffer(config, conn_config->cert_blob->data,
                                   (uint32_t)conn_config->cert_blob->len,
                                   HITLS_PARSE_FORMAT_PEM);
    if(ret != HITLS_SUCCESS) {
      failf(data, "Failed to load client certificate from blob");
      HITLS_CFG_FreeConfig(config);
      return CURLE_SSL_CERTPROBLEM;
    }
  }

  /* Set private key if configured */
  if(ssl_config->key) {
    ret = HITLS_CFG_LoadKeyFile(config, ssl_config->key, HITLS_PARSE_FORMAT_PEM);
    if(ret != HITLS_SUCCESS) {
      failf(data, "Failed to load private key: %s", ssl_config->key);
      HITLS_CFG_FreeConfig(config);
      return CURLE_SSL_CONNECT_ERROR;
    }
  }

  /* Set private key from blob if configured */
  if(ssl_config->key_blob) {
    ret = HITLS_CFG_LoadKeyBuffer(config, ssl_config->key_blob->data,
                                  (uint32_t)ssl_config->key_blob->len,
                                  HITLS_PARSE_FORMAT_PEM);
    if(ret != HITLS_SUCCESS) {
      failf(data, "Failed to load private key from blob");
      HITLS_CFG_FreeConfig(config);
      return CURLE_SSL_CONNECT_ERROR;
    }
  }

  /* Create SSL context */
  ctx = HITLS_New(config);
  if(!ctx) {
    failf(data, "Failed to create openHiTLS context");
    HITLS_CFG_FreeConfig(config);
    return CURLE_OUT_OF_MEMORY;
  }

  /* Set endpoint - curl always acts as client */
  ret = HITLS_SetEndPoint(ctx, true);
  if(ret != HITLS_SUCCESS) {
    failf(data, "Failed to set endpoint");
    HITLS_Free(ctx);
    HITLS_CFG_FreeConfig(config);
    return CURLE_SSL_CONNECT_ERROR;
  }

  /* Create and set BIO */
  bio = BSL_UIO_New(openhitls_bio_cf_method());
  if(!bio) {
    failf(data, "Failed to create BIO");
    HITLS_Free(ctx);
    HITLS_CFG_FreeConfig(config);
    return CURLE_OUT_OF_MEMORY;
  }

  BSL_UIO_SetUserData(bio, cf);
  
  ret = HITLS_SetUio(ctx, bio);
  if(ret != HITLS_SUCCESS) {
    failf(data, "Failed to set BIO");
    BSL_UIO_Free(bio);
    HITLS_Free(ctx);
    HITLS_CFG_FreeConfig(config);
    return CURLE_SSL_CONNECT_ERROR;
  }

  /* Set SNI if available */
  if(connssl->peer.sni) {
    ret = HITLS_SetServerName(ctx, (uint8_t *)connssl->peer.sni,
                              (uint32_t)strlen(connssl->peer.sni));
    if(ret != HITLS_SUCCESS) {
      /* Non-fatal, continue without SNI */
      infof(data, "Failed to set SNI");
    }
  }

  /* Set ALPN */
  if(connssl->alpn) {
    struct alpn_proto_buf proto;
    Curl_alpn_to_proto_buf(&proto, connssl->alpn);
    
    ret = HITLS_SetAlpnProtos(ctx, proto.data, proto.len);
    if(ret != HITLS_SUCCESS) {
      /* Non-fatal, continue without ALPN */
      infof(data, "Failed to set ALPN");
    }
  }

  /* Save context */
  octx->config = config;
  octx->ctx = ctx;
  octx->bio = bio;

  return CURLE_OK;
}

static CURLcode openhitls_connect_common(struct Curl_cfilter *cf,
                                        struct Curl_easy *data,
                                        bool *done)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct ssl_primary_config *conn_config = Curl_ssl_cf_get_primary_config(cf);
  struct openhitls_ssl_backend_data *backend = connssl->backend;
  struct openhitls_ctx *octx = &backend->openhitls;
  int ret;
  CURLcode result = CURLE_OK;

  *done = FALSE;

  if(!octx->ctx) {
    result = openhitls_connect_init(cf, data);
    if(result)
      return result;
  }

  /* Perform handshake - curl always acts as client */
  ret = HITLS_Connect(octx->ctx);

  if(ret == HITLS_SUCCESS) {
    *done = TRUE;
    connssl->state = ssl_connection_complete;
    
    /* Get negotiated ALPN */
    uint8_t *alpn_data = NULL;
    uint32_t alpn_len = 0;
    ret = HITLS_GetSelectedAlpnProto(octx->ctx, &alpn_data, &alpn_len);
    if(ret == HITLS_SUCCESS && alpn_data && alpn_len > 0) {
      Curl_alpn_set_negotiated(cf, data, connssl, alpn_data, alpn_len);
    }
    
    /* Get server certificate for verification */
    if(conn_config->verifypeer || conn_config->verifyhost) {
      HITLS_CERT_X509 *cert = HITLS_GetPeerCertificate(octx->ctx);
      if(cert) {
        /* Verify hostname */
        if(conn_config->verifyhost) {
          /* TODO: Implement proper hostname verification with openHiTLS */
          infof(data, "Hostname verification not yet implemented for openHiTLS");
        }
        octx->server_cert = cert;
      }
    }
    
    return CURLE_OK;
  }
  else if(ret == HITLS_REC_NORMAL_RECV_BUF_EMPTY) {
    connssl->io_need = CURL_SSL_IO_NEED_RECV;
    return CURLE_OK;
  }
  else if(ret == HITLS_REC_NORMAL_IO_BUSY) {
    connssl->io_need = CURL_SSL_IO_NEED_SEND;
    return CURLE_OK;
  }
  else {
    failf(data, "openHiTLS handshake error: %d", ret);
    return CURLE_SSL_CONNECT_ERROR;
  }
}

static CURLcode openhitls_connect_step1(struct Curl_cfilter *cf,
                                       struct Curl_easy *data)
{
  bool done;
  return openhitls_connect_common(cf, data, &done);
}

static CURLcode openhitls_connect_step2(struct Curl_cfilter *cf,
                                       struct Curl_easy *data)
{
  bool done;
  return openhitls_connect_common(cf, data, &done);
}

static CURLcode openhitls_connect(struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 bool *done)
{
  struct ssl_connect_data *connssl = cf->ctx;
  CURLcode result = CURLE_OK;

  if(connssl->state == ssl_connection_complete) {
    *done = TRUE;
    return CURLE_OK;
  }

  if(connssl->connecting_state == ssl_connect_1) {
    result = openhitls_connect_step1(cf, data);
    if(result)
      return result;
    connssl->connecting_state = ssl_connect_2;
  }

  if(connssl->connecting_state == ssl_connect_2) {
    result = openhitls_connect_step2(cf, data);
    if(result)
      return result;
    connssl->connecting_state = ssl_connect_3;
  }

  if(connssl->connecting_state == ssl_connect_3) {
    result = openhitls_connect_common(cf, data, done);
    if(result)
      return result;
    
    if(*done) {
      connssl->connecting_state = ssl_connect_done;
    }
  }

  return result;
}

static bool openhitls_data_pending(struct Curl_cfilter *cf,
                                  const struct Curl_easy *data)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct openhitls_ssl_backend_data *backend = connssl->backend;
  struct openhitls_ctx *octx = &backend->openhitls;

  (void)data;
  DEBUGASSERT(backend);

  if(!octx->ctx)
    return FALSE;

  return HITLS_GetReadPendingBytes(octx->ctx) > 0;
}

static ssize_t openhitls_recv(struct Curl_cfilter *cf,
                             struct Curl_easy *data,
                             char *buf, size_t buffersize,
                             CURLcode *curlcode)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct openhitls_ssl_backend_data *backend = connssl->backend;
  struct openhitls_ctx *octx = &backend->openhitls;
  uint32_t read_len = 0;
  int ret;

  DEBUGASSERT(backend);

  ret = HITLS_Read(octx->ctx, (uint8_t *)buf, (uint32_t)buffersize, &read_len);
  
  if(ret == HITLS_SUCCESS && read_len > 0) {
    *curlcode = CURLE_OK;
    return (ssize_t)read_len;
  }
  else if(ret == HITLS_REC_NORMAL_RECV_BUF_EMPTY) {
    *curlcode = CURLE_AGAIN;
    return -1;
  }
  else if(ret == HITLS_REC_NORMAL_IO_BUSY) {
    *curlcode = CURLE_AGAIN;
    return -1;
  }
  else if(ret == HITLS_CM_LINK_CLOSED) {
    *curlcode = CURLE_OK;
    return 0;
  }
  else {
    failf(data, "openHiTLS read error: %d", ret);
    *curlcode = CURLE_RECV_ERROR;
    return -1;
  }
}

static ssize_t openhitls_send(struct Curl_cfilter *cf,
                             struct Curl_easy *data,
                             const void *mem, size_t len,
                             CURLcode *curlcode)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct openhitls_ssl_backend_data *backend = connssl->backend;
  struct openhitls_ctx *octx = &backend->openhitls;
  uint32_t written = 0;
  int ret;

  DEBUGASSERT(backend);

  ret = HITLS_Write(octx->ctx, (const uint8_t *)mem, (uint32_t)len, &written);
  
  if(ret == HITLS_SUCCESS && written > 0) {
    *curlcode = CURLE_OK;
    return (ssize_t)written;
  }
  else if(ret == HITLS_REC_NORMAL_RECV_BUF_EMPTY) {
    *curlcode = CURLE_AGAIN;
    return -1;
  }
  else if(ret == HITLS_REC_NORMAL_IO_BUSY) {
    *curlcode = CURLE_AGAIN;
    return -1;
  }
  else {
    failf(data, "openHiTLS write error: %d", ret);
    *curlcode = CURLE_SEND_ERROR;
    return -1;
  }
}

static size_t openhitls_version(char *buffer, size_t size)
{
  return msnprintf(buffer, size, "openHiTLS");
}

static CURLcode openhitls_random(struct Curl_easy *data,
                                unsigned char *entropy, size_t length)
{
  (void)data;
  
  /* Use openHiTLS random number generator */
  int ret = CRYPT_EAL_RandBytes(entropy, (uint32_t)length);
  if(ret != 0) {
    return CURLE_FAILED_INIT;
  }
  
  return CURLE_OK;
}

static void *openhitls_get_internals(struct ssl_connect_data *connssl,
                                    CURLINFO info)
{
  struct openhitls_ssl_backend_data *backend = connssl->backend;
  struct openhitls_ctx *octx = &backend->openhitls;
  
  DEBUGASSERT(backend);
  
  return info == CURLINFO_TLS_SESSION ?
    (void *)octx->config : (void *)octx->ctx;
}

static void openhitls_close_all(struct Curl_easy *data)
{
  (void)data;
  /* openHiTLS doesn't require global cleanup per connection */
}

const struct Curl_ssl Curl_ssl_openhitls = {
  { CURLSSLBACKEND_OPENHITLS, "openhitls" }, /* info */

  SSLSUPP_CA_PATH |
  SSLSUPP_CAINFO_BLOB |
  SSLSUPP_SSL_CTX |
  SSLSUPP_HTTPS_PROXY |
  SSLSUPP_CIPHER_LIST,

  sizeof(struct openhitls_ssl_backend_data),

  openhitls_init,                   /* init */
  openhitls_cleanup,                /* cleanup */
  openhitls_version,                /* version */
  openhitls_shutdown,               /* shutdown */
  openhitls_data_pending,           /* data_pending */
  openhitls_random,                 /* random */
  NULL,                             /* cert_status_request */
  openhitls_connect,                /* connect */
  Curl_ssl_adjust_pollset,          /* adjust_pollset */
  openhitls_get_internals,          /* get_internals */
  openhitls_close,                  /* close_one */
  openhitls_close_all,              /* close_all */
  NULL,                             /* set_engine */
  NULL,                             /* set_engine_default */
  NULL,                             /* engines_list */
  NULL,                             /* sha256sum */
  openhitls_recv,                   /* recv decrypted data */
  openhitls_send,                   /* send data to encrypt */
  NULL,                             /* get_channel_binding */
};

#endif /* USE_OPENHITLS */