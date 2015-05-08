/*
 * ssl_engine_verify.h
 * Copyright (C) 2002 IDEALX
 * All rights reserved.
 *
 * $Id: ssl_engine_verify.h,v 1.4 2002/10/24 22:51:11 mbrossard Exp $
 *
 * This file defines an modified function for the verification of the
 * client certificate by mod_ssl. With this function, the client
 * certificate and the CRL can be signed by two differents keys owned
 * by an only one CA (the keys used for certificate signing and CRL
 * signing are not the same but the DN matches).
 *
 * Work based is based on the OpenSSL sources, version 0.9.6g
 * Please look at http://www.openssl.org/ for more information
 *
 * Authors:
 *   Designed by:
 *     - Dominique QUATRAVEAUX <dominique.quatraveaux@idealx.com>
 *     - Mathias BROSSARD <mathias.brossard@idealx.com>
 *   Written by:
 *     - Mathias BROSSARD <mathias.brossard@idealx.com>
 * 
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com) and by Tim Hudson (tjh@cryptsoft.com).
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 * 
 * The licence and distribution terms for any publically available
 * version or derivative of this code cannot be changed. i.e. this
 * code cannot simply be copied and put under another distribution
 * licence [including the GNU Public Licence.]
 */
#ifndef _SSL_ENGINE_VERIFY_H_
#define _SSL_ENGINE_VERIFY_H_

#include <openssl/x509_vfy.h>

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

  /* This function replaces X509_verify_cert() as callback for the
   * certificate verification.
   */
  int ssl_verify(X509_STORE_CTX *ctx, void *dummy);
  int ssl_verify_error(int ok, X509_STORE_CTX *ctx);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _VERIFY_CERT_H_ */
