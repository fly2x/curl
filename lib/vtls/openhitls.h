#ifndef HEADER_CURL_OPENHITLS_H
#define HEADER_CURL_OPENHITLS_H
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

#ifdef USE_OPENHITLS

#include "../curl_setup.h"

extern const struct Curl_ssl Curl_ssl_openhitls;

struct openhitls_ctx {
  HITLS_Config *config;
  HITLS_Ctx *ctx;
  HITLS_CERT_X509 *server_cert;
  BSL_UIO *bio;
  HITLS_X509_StoreCtx *store_ctx;
};

#endif /* USE_OPENHITLS */
#endif /* HEADER_CURL_OPENHITLS_H */