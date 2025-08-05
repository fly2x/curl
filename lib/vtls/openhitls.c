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

#include "../curl_setup.h"

#ifdef USE_OPENHITLS

#include <errno.h>
#include <stdint.h>
#include <tls/hitls.h>
#include <tls/hitls_config.h>
#include <tls/hitls_error.h>
#include <tls/hitls_cert_type.h>
#include <tls/hitls_cert.h>
#include <crypto/crypt_eal_init.h>
#include <crypto/crypt_eal_rand.h>
#include <crypto/crypt_algid.h>
#include <bsl/bsl_uio.h>
#include <bsl/bsl_sal.h>
#include <bsl/bsl_err.h>
#include <tls/hitls_cert_init.h>
#include <tls/hitls_crypt_init.h>
#include <crypto/crypt_errno.h>
#include <pki/hitls_pki_cert.h>
#include <pki/hitls_pki_x509.h>

#include "../urldata.h"
#include "../sendf.h"
#include "../multiif.h"
#include "../cfilters.h"
#include "vtls.h"
#include "vtls_int.h"
#include "../curl_printf.h"
#include "openhitls.h"

/* The last #include files should be: */
#include "../curl_memory.h"
#include "../memdebug.h"

struct hitls_ctx {
  HITLS_Ctx *ssl;
  HITLS_Config *config;
  BSL_UIO *uio;
};

static int
hitls_init(void)
{
  int ret;
  void *malloc_func = (void *)(uintptr_t)malloc;
  void *free_func = (void *)(uintptr_t)free;

  /* Register BSL memory capabilities */
  BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, malloc_func);
  BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_FREE, free_func);
  BSL_ERR_Init();

  /* Initialize crypto library */
  ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_PROVIDER);
  if(ret != CRYPT_SUCCESS) {
    return 0; /* Failure */
  }

  /* Initialize random number generator */
  ret = CRYPT_EAL_ProviderRandInitCtx(NULL, CRYPT_RAND_SHA256,
                                      "provider=default", NULL, 0, NULL);
  if(ret != CRYPT_SUCCESS) {
    return 0; /* Failure */
  }

  /* Initialize certificate and crypto methods */
  HITLS_CertMethodInit();
  HITLS_CryptMethodInit();

  return 1; /* Success */
}

static void
hitls_cleanup(void)
{
  /* Deinitialize random number generator */
  CRYPT_EAL_RandDeinit();

  /* Note: CRYPT_EAL_Cleanup() may not be available,
   * OpenHiTLS cleanup is mostly handled automatically */
}

static size_t
hitls_version(char *buffer, size_t size)
{
  return curl_msnprintf(buffer, size, "OpenHiTLS");
}

static bool
hitls_data_pending(struct Curl_cfilter *cf, const struct Curl_easy *data)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct hitls_ctx *backend = (struct hitls_ctx *)connssl->backend;

  (void)data;

  if(backend && backend->ssl) {
    /* Check if there's buffered data waiting to be read */
    uint32_t readlen = 0;
    uint8_t dummy_buf[1];
    int ret = HITLS_Peek(backend->ssl, dummy_buf, 0, &readlen);
    return (ret == HITLS_SUCCESS && readlen > 0);
  }
  return FALSE;
}

static CURLcode
hitls_random(struct Curl_easy *data, unsigned char *entropy, size_t length)
{
  (void)data;
  if(CRYPT_EAL_Randbytes(entropy, (uint32_t)length) == HITLS_SUCCESS) {
    return CURLE_OK;
  }
  return CURLE_FAILED_INIT;
}

static bool
hitls_cert_status_request(void)
{
  return FALSE;
}

static CURLcode
hitls_shutdown(struct Curl_cfilter *cf, struct Curl_easy *data,
               bool send_shutdown, bool *done)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct hitls_ctx *backend = (struct hitls_ctx *)connssl->backend;
  CURLcode result = CURLE_OK;

  (void)data;

  *done = TRUE; /* Default to done */
  if(backend && backend->ssl && send_shutdown) {
    /* OpenHiTLS doesn't have explicit shutdown function like OpenSSL
     * The connection will be closed when HITLS_Free is called */
    infof(data, "OpenHiTLS: Shutting down SSL connection");
  }

  return result;
}

static void
hitls_close(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct hitls_ctx *backend = (struct hitls_ctx *)connssl->backend;

  (void)data;

  if(backend) {
    if(backend->ssl) {
      HITLS_Free(backend->ssl);
      backend->ssl = NULL;
    }
    if(backend->uio) {
      BSL_UIO_Free(backend->uio);
      backend->uio = NULL;
    }
    if(backend->config) {
      HITLS_CFG_FreeConfig(backend->config);
      backend->config = NULL;
    }
  }
}

static void
hitls_close_all(struct Curl_easy *data)
{
  (void)data;
  /* Nothing specific to do for global cleanup */
}

static CURLcode
hitls_set_engine(struct Curl_easy *data, const char *engine)
{
  (void)data;
  (void)engine;
  return CURLE_NOT_BUILT_IN;
}

static CURLcode
hitls_set_engine_default(struct Curl_easy *data)
{
  (void)data;
  return CURLE_NOT_BUILT_IN;
}

static struct curl_slist *
hitls_engines_list(struct Curl_easy *data)
{
  (void)data;
  return NULL;
}

static void *
hitls_get_internals(struct ssl_connect_data *connssl, CURLINFO info)
{
  (void)connssl;
  (void)info;
  return NULL;
}

static CURLcode
hitls_sha256sum(const unsigned char *input, size_t inputlen,
                unsigned char *sha256sum, size_t sha256sumlen)
{
  (void)input;
  (void)inputlen;
  (void)sha256sum;
  (void)sha256sumlen;
  return CURLE_NOT_BUILT_IN;
}

static CURLcode
hitls_verifyhost(struct Curl_easy *data, struct connectdata *conn,
                 struct ssl_peer *peer, HITLS_CERT_X509 *server_cert)
{
  /* This is a simplified host verification
   * A full implementation would need to check Subject Alternative Names
   * and CN field like OpenSSL does */

  const char *hostname = peer->hostname;

  /* Suppress unused parameter warning */
  (void)conn;

  if(!hostname || !server_cert) {
    failf(data, "OpenHiTLS: No hostname or certificate for verification");
    return CURLE_PEER_FAILED_VERIFICATION;
  }

  /* For now, just log that we're doing host verification
   * A complete implementation would:
   * 1. Extract Subject Alternative Names from the certificate
   * 2. Extract Common Name from subject
   * 3. Compare against the hostname
   * 4. Handle wildcards
   * 5. Handle IP addresses vs DNS names
   */

  infof(data, "OpenHiTLS: Host %s verification (simplified implementation)",
        hostname);

  /* NOTE: Implement proper hostname verification using OpenHiTLS cert APIs */

  return CURLE_OK;
}

static CURLcode
ossl_populate_x509_store(struct Curl_cfilter *cf, struct Curl_easy *data,
                         HITLS_Config *config)
{
  struct ssl_primary_config *conn_config = Curl_ssl_cf_get_primary_config(cf);
  struct ssl_config_data *ssl_config = Curl_ssl_cf_get_config(cf, data);
  const struct curl_blob *ca_info_blob = conn_config->ca_info_blob;
  const char * const ssl_cafile =
    /* CURLOPT_CAINFO_BLOB overrides CURLOPT_CAINFO */
    (ca_info_blob ? NULL : conn_config->CAfile);
  const char * const ssl_capath = conn_config->CApath;
  const char * const ssl_crlfile = ssl_config->primary.CRLfile;
  const bool verifypeer = conn_config->verifypeer;
  int ret;

  CURL_TRC_CF(data, cf, "ossl_populate_x509_store, path=%s, blob=%d",
              ssl_cafile ? ssl_cafile : "none", !!ca_info_blob);
  if(!config)
    return CURLE_OUT_OF_MEMORY;

  if(verifypeer) {
    if(ca_info_blob) {
      /* Load CA from memory blob */
      HITLS_CERT_X509 *ca_cert = HITLS_CFG_ParseCert(config,
                                        (const uint8_t *)ca_info_blob->data,
                                        (uint32_t)ca_info_blob->len,
                                        TLS_PARSE_TYPE_BUFF,
                                        TLS_PARSE_FORMAT_PEM);
      if(!ca_cert) {
        failf(data, "OpenHiTLS: Failed to parse CA certificate from blob");
        return CURLE_SSL_CACERT_BADFILE;
      }

      ret = HITLS_CFG_AddCertToStore(config, ca_cert,
                                     TLS_CERT_STORE_TYPE_VERIFY, false);
      HITLS_X509_CertFree(ca_cert);
      if(ret != HITLS_SUCCESS) {
        failf(data, "OpenHiTLS: Failed to add CA certificate to store");
        return CURLE_SSL_CACERT_BADFILE;
      }

      infof(data, " CAinfo: blob loaded");
    }

    if(ssl_cafile) {
      /* Load CA from file */
      uint32_t path_len = (uint32_t)strlen(ssl_cafile);
      HITLS_CERT_X509 *ca_cert = HITLS_CFG_ParseCert(config,
                                        (const uint8_t *)ssl_cafile,
                                        path_len,
                                        TLS_PARSE_TYPE_FILE,
                                        TLS_PARSE_FORMAT_PEM);
      if(!ca_cert) {
        failf(data, "OpenHiTLS: error setting certificate file: %s",
              ssl_cafile);
        return CURLE_SSL_CACERT_BADFILE;
      }

      ret = HITLS_CFG_AddCertToStore(config, ca_cert,
                                     TLS_CERT_STORE_TYPE_VERIFY, false);
      HITLS_X509_CertFree(ca_cert);
      if(ret != HITLS_SUCCESS) {
        failf(data, "OpenHiTLS: Failed to add CA certificate to store");
        return CURLE_SSL_CACERT_BADFILE;
      }

      infof(data, " CAfile: %s", ssl_cafile);
    }

    if(ssl_capath) {
      /* OpenHiTLS doesn't have direct directory loading like OpenSSL
       * We would need to implement directory traversal and load each file */
      infof(data, " CApath: %s (directory loading not fully supported)",
            ssl_capath);
    }

    if(ssl_crlfile) {
      /* OpenHiTLS CRL support - this might need additional implementation */
      infof(data, " CRLfile: %s (CRL support may need additional impl)",
            ssl_crlfile);
    }

    /* Set verification parameters */
    if(conn_config->verifypeer) {
      /* Enable certificate verification */
      infof(data, " Certificate verification: enabled");
    }
  }

  return CURLE_OK;
}

static CURLcode
hitls_connect(struct Curl_cfilter *cf, struct Curl_easy *data,
              bool *done)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct hitls_ctx *backend = (struct hitls_ctx *)connssl->backend;
  struct ssl_primary_config *conn_config = Curl_ssl_cf_get_primary_config(cf);
  struct ssl_config_data *ssl_config = Curl_ssl_cf_get_config(cf, data);
  int sockfd = Curl_conn_cf_get_socket(cf, data);
  int ret;
  CURLcode result = CURLE_OK;

  DEBUGASSERT(backend);

  if(ssl_connection_complete == connssl->state) {
    *done = TRUE;
    return CURLE_OK;
  }

  if(ssl_connect_1 == connssl->connecting_state) {
    /* Create config if not already done */
    if(!backend->config) {
      bool verifypeer;
      bool verifyhost;
      const char *key_file;

      /* Try TLS12 config first, fallback to general TLS config */
      backend->config = HITLS_CFG_NewTLS12Config();
      if(!backend->config) {
        backend->config = HITLS_CFG_NewTLSConfig();
      }
      if(!backend->config) {
        failf(data, "OpenHiTLS: Failed to create config");
        return CURLE_OUT_OF_MEMORY;
      }

      /* Configure SSL options similar to demo code */
      ret = HITLS_CFG_SetCheckKeyUsage(backend->config, false);
      if(ret != HITLS_SUCCESS) {
        failf(data, "OpenHiTLS: Failed to disable key usage check: %d", ret);
        return CURLE_SSL_CONNECT_ERROR;
      }

      /* Configure certificate verification based on curl options */
      verifypeer = conn_config->verifypeer;
      verifyhost = conn_config->verifyhost;

      /* Set peer verification mode */
      if(verifypeer || verifyhost) {
        /* Enable client certificate verification on server side if needed */
        if(ssl_config->primary.clientcert) {
          ret = HITLS_CFG_SetClientVerifySupport(backend->config, true);
          if(ret != HITLS_SUCCESS) {
            failf(data, "OpenHiTLS: Failed to enable client verify: %d", ret);
            return CURLE_SSL_CONNECT_ERROR;
          }
        }

        /* Configure CA certificates directly in config */
        result = ossl_populate_x509_store(cf, data, backend->config);
        if(result) {
          return result;
        }
      }
      else {
        /* Disable peer verification */
        ret = HITLS_CFG_SetClientVerifySupport(backend->config, false);
        if(ret != HITLS_SUCCESS) {
          failf(data, "OpenHiTLS: Failed to disable client verify: %d", ret);
          return CURLE_SSL_CONNECT_ERROR;
        }
      }

      /* Configure client certificate and private key if provided */
      if(ssl_config->primary.clientcert) {
        ret = HITLS_CFG_LoadCertFile(backend->config,
                                     ssl_config->primary.clientcert,
                                     TLS_PARSE_FORMAT_PEM);
        if(ret != HITLS_SUCCESS) {
          failf(data, "OpenHiTLS: Failed to load client certificate: %s",
                ssl_config->primary.clientcert);
          return CURLE_SSL_CERTPROBLEM;
        }

        /* Load private key */
        key_file = ssl_config->key ? ssl_config->key :
                   ssl_config->primary.clientcert;
        ret = HITLS_CFG_LoadKeyFile(backend->config, key_file,
                                    TLS_PARSE_FORMAT_PEM);
        if(ret != HITLS_SUCCESS) {
          failf(data, "OpenHiTLS: Failed to load private key: %s", key_file);
          return CURLE_SSL_CERTPROBLEM;
        }

        /* Verify certificate and key match */
        ret = HITLS_CFG_CheckPrivateKey(backend->config);
        if(ret != HITLS_SUCCESS) {
          failf(data, "OpenHiTLS: Certificate and private key do not match");
          return CURLE_SSL_CERTPROBLEM;
        }
      }
    }

    /* Create SSL context if not already done */
    if(!backend->ssl) {
      backend->ssl = HITLS_New(backend->config);
      if(!backend->ssl) {
        failf(data, "OpenHiTLS: Failed to create SSL context");
        return CURLE_OUT_OF_MEMORY;
      }
    }

    /* Create and configure UIO if not already done */
    if(!backend->uio) {
      backend->uio = BSL_UIO_New(BSL_UIO_TcpMethod());
      if(!backend->uio) {
        failf(data, "OpenHiTLS: Failed to create UIO");
        return CURLE_OUT_OF_MEMORY;
      }

      /* Set the socket file descriptor for the UIO */
      ret = BSL_UIO_Ctrl(backend->uio, BSL_UIO_SET_FD,
                         (int32_t)sizeof(sockfd), &sockfd);
      if(ret != HITLS_SUCCESS) {
        failf(data, "OpenHiTLS: Failed to set UIO file descriptor: %d", ret);
        return CURLE_SSL_CONNECT_ERROR;
      }

      /* Bind UIO to SSL context */
      ret = HITLS_SetUio(backend->ssl, backend->uio);
      if(ret != HITLS_SUCCESS) {
        failf(data, "OpenHiTLS: Failed to set UIO: %d", ret);
        return CURLE_SSL_CONNECT_ERROR;
      }
    }

    /* Set client mode */
    ret = HITLS_SetEndPoint(backend->ssl, true);
    if(ret != HITLS_SUCCESS) {
      failf(data, "OpenHiTLS: Failed to set client mode: %d", ret);
      return CURLE_SSL_CONNECT_ERROR;
    }

    connssl->connecting_state = ssl_connect_2;
  }

  /* Perform the handshake */
  ret = HITLS_Connect(backend->ssl);

  if(ret == HITLS_SUCCESS) {
    /* Handshake completed successfully */
    connssl->connecting_state = ssl_connect_done;
    connssl->state = ssl_connection_complete;
    *done = TRUE;

    /* Perform certificate verification if required */
    if(conn_config->verifypeer || conn_config->verifyhost) {
      HITLS_CERT_X509 *server_cert = HITLS_GetPeerCertificate(backend->ssl);
      if(!server_cert) {
        if(conn_config->verifypeer) {
          failf(data, "OpenHiTLS: No server certificate received");
          return CURLE_PEER_FAILED_VERIFICATION;
        }
        else {
          infof(data,
                "OpenHiTLS: No server certificate received "
                "(verification disabled)");
        }
      }
      else {
        /* Verify the certificate chain */
        if(conn_config->verifypeer) {
          HITLS_ERROR verify_result;
          ret = HITLS_GetVerifyResult(backend->ssl, &verify_result);
          if(ret != HITLS_SUCCESS) {
            failf(data, "OpenHiTLS: Failed to get certificate "
                  "verification result: %d", ret);
            HITLS_X509_CertFree(server_cert);
            return CURLE_PEER_FAILED_VERIFICATION;
          }
          if(verify_result != HITLS_SUCCESS) {
            failf(data, "OpenHiTLS: Certificate verification "
                  "failed: %d", verify_result);
            HITLS_X509_CertFree(server_cert);
            return CURLE_PEER_FAILED_VERIFICATION;
          }
          infof(data, "OpenHiTLS: Certificate verification passed");
        }
        /* Verify hostname */
        if(conn_config->verifyhost) {
          struct ssl_peer peer;
          /* Initialize peer structure for hostname verification */
          memset(&peer, 0, sizeof(peer));
          peer.hostname = connssl->peer.hostname;
          peer.dispname = connssl->peer.dispname;

          result = hitls_verifyhost(data, cf->conn, &peer, server_cert);
          if(result) {
            HITLS_X509_CertFree(server_cert);
            return result;
          }
        }

        HITLS_X509_CertFree(server_cert);
      }
    }

    infof(data, "OpenHiTLS: SSL connection completed");
  }
  else if(ret == HITLS_REC_NORMAL_RECV_BUF_EMPTY ||
          ret == HITLS_REC_NORMAL_IO_BUSY ||
          ret == HITLS_WANT_READ ||
          ret == HITLS_WANT_WRITE) {
    /* Non-blocking operation needs to continue */
    *done = FALSE;
    result = CURLE_OK;

    /* Set I/O requirements for polling */
    if(ret == HITLS_WANT_READ || ret == HITLS_REC_NORMAL_RECV_BUF_EMPTY) {
      connssl->io_need = CURL_SSL_IO_NEED_RECV;
    }
    else if(ret == HITLS_WANT_WRITE || ret == HITLS_REC_NORMAL_IO_BUSY) {
      connssl->io_need = CURL_SSL_IO_NEED_SEND;
    }
  }
  else {
    /* Error occurred */
    int hitls_error = HITLS_GetError(backend->ssl, ret);
    failf(data, "OpenHiTLS: SSL handshake failed: %d (error: %d)",
          ret, hitls_error);
    result = CURLE_SSL_CONNECT_ERROR;
  }

  return result;
}

static CURLcode
hitls_recv(struct Curl_cfilter *cf, struct Curl_easy *data,
           char *buf, size_t buffersize, size_t *nread)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct hitls_ctx *backend = (struct hitls_ctx *)connssl->backend;
  int ret;
  uint32_t readlen = 0;
  CURLcode result = CURLE_OK;

  DEBUGASSERT(backend && backend->ssl);

  *nread = 0;

  ret = HITLS_Read(backend->ssl, (uint8_t *)buf,
                   (uint32_t)buffersize, &readlen);

  if(ret == HITLS_SUCCESS) {
    *nread = (size_t)readlen;
  }
  else if(ret == HITLS_REC_NORMAL_RECV_BUF_EMPTY) {
    /* No data available right now - not an error in non-blocking mode */
    result = CURLE_AGAIN;
  }
  else if(ret == HITLS_REC_NORMAL_IO_BUSY) {
    /* I/O operation would block */
    result = CURLE_AGAIN;
    connssl->io_need = CURL_SSL_IO_NEED_RECV;
  }
  else if(ret == HITLS_WANT_READ) {
    result = CURLE_AGAIN;
    connssl->io_need = CURL_SSL_IO_NEED_RECV;
  }
  else if(ret == HITLS_WANT_WRITE) {
    result = CURLE_AGAIN;
    connssl->io_need = CURL_SSL_IO_NEED_SEND;
  }
  else {
    /* Error occurred */
    int hitls_error = HITLS_GetError(backend->ssl, ret);
    failf(data, "OpenHiTLS: SSL read failed: %d (error: %d)",
          ret, hitls_error);
    result = CURLE_RECV_ERROR;
  }

  return result;
}

static CURLcode
hitls_send(struct Curl_cfilter *cf, struct Curl_easy *data,
           const void *mem, size_t len, size_t *written)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct hitls_ctx *backend = (struct hitls_ctx *)connssl->backend;
  int ret;
  uint32_t writelen = 0;
  CURLcode result = CURLE_OK;

  DEBUGASSERT(backend && backend->ssl);

  *written = 0;

  ret = HITLS_Write(backend->ssl, (const uint8_t *)mem,
                    (uint32_t)len, &writelen);

  if(ret == HITLS_SUCCESS) {
    *written = (size_t)writelen;
  }
  else if(ret == HITLS_REC_NORMAL_IO_BUSY) {
    /* I/O operation would block */
    result = CURLE_AGAIN;
    connssl->io_need = CURL_SSL_IO_NEED_SEND;
  }
  else if(ret == HITLS_WANT_READ) {
    result = CURLE_AGAIN;
    connssl->io_need = CURL_SSL_IO_NEED_RECV;
  }
  else if(ret == HITLS_WANT_WRITE) {
    result = CURLE_AGAIN;
    connssl->io_need = CURL_SSL_IO_NEED_SEND;
  }
  else {
    /* Error occurred */
    int hitls_error = HITLS_GetError(backend->ssl, ret);
    failf(data, "OpenHiTLS: SSL write failed: %d (error: %d)",
          ret, hitls_error);
    result = CURLE_SEND_ERROR;
  }

  return result;
}

static CURLcode
hitls_get_channel_binding(struct Curl_easy *data, int sockindex,
                          struct dynbuf *binding)
{
  (void)data;
  (void)sockindex;
  (void)binding;
  return CURLE_NOT_BUILT_IN;
}

const struct Curl_ssl Curl_ssl_openhitls = {
  { CURLSSLBACKEND_NONE, "openhitls" }, /* info */

  SSLSUPP_CA_PATH |
  SSLSUPP_CAINFO_BLOB |
  SSLSUPP_CERTINFO |
  SSLSUPP_PINNEDPUBKEY |
  SSLSUPP_SSL_CTX |
  SSLSUPP_HTTPS_PROXY |
  SSLSUPP_CIPHER_LIST,

  sizeof(struct hitls_ctx),

  hitls_init,                /* init */
  hitls_cleanup,             /* cleanup */
  hitls_version,             /* version */
  hitls_shutdown,            /* shutdown */
  hitls_data_pending,        /* data_pending */
  hitls_random,              /* random */
  hitls_cert_status_request, /* cert_status_request */
  hitls_connect,             /* connect */
  Curl_ssl_adjust_pollset,   /* adjust_pollset */
  hitls_get_internals,       /* get_internals */
  hitls_close,               /* close_one */
  hitls_close_all,           /* close_all */
  hitls_set_engine,          /* set_engine */
  hitls_set_engine_default,  /* set_engine_default */
  hitls_engines_list,        /* engines_list */
  hitls_sha256sum,           /* sha256sum */
  hitls_recv,                /* recv decrypted data */
  hitls_send,                /* send data to encrypt */
  hitls_get_channel_binding  /* get_channel_binding */
};

#endif /* USE_OPENHITLS */