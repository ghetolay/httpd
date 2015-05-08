/*
 * ssl_engine_verify.c
 * Copyright (C) 2002,2005 IDEALX
 * All rights reserved.
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
 *     - Nicolas Delon <nicolas.delon@idealx.com>
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

#include <stdio.h>
#include <time.h>
#include <errno.h>

#include <openssl/crypto.h>
#include <openssl/lhash.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/objects.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>

#include "ssl_engine_verify.h"

/************* Début modification ASIP Santé 20111014 ***************/
/* #include "mod_ssl.h" */
   #include "ssl_private.h"
/************* Fin modification ASIP Santé 20111014 ***************/

/* static int ca_check(const X509 *x);
 *
 * This function comes from OpenSSL but isn't exported.
 * return codes:
 * 0 not a CA
 * 1 is a CA
 * 2 basicConstraints absent so "maybe" a CA
 * 3 basicConstraints absent but self signed V1.
 */
#define V1_ROOT (EXFLAG_V1|EXFLAG_SS)
#define ku_reject(x, usage) \
	(((x)->ex_flags & EXFLAG_KUSAGE) && !((x)->ex_kusage & (usage)))

static int ca_check(const X509 *x)
{
  /* keyUsage if present should allow cert signing */
  if(ku_reject(x, KU_KEY_CERT_SIGN)) return 0;
  if(x->ex_flags & EXFLAG_BCONS) {
    if(x->ex_flags & EXFLAG_CA) return 1;
    /* If basicConstraints says not a CA then say so */
    else return 0;
  } else {
    if((x->ex_flags & V1_ROOT) == V1_ROOT) return 3;
    /* If key usage present it must have certSign so tolerate it */
    else if (x->ex_flags & EXFLAG_KUSAGE) return 3;
    else return 2;
  }
}

/* int check_is_issuer(X509 *a, X509 *ca)
 *
 * This function checks that "ca" is a valid CA for "a" meaning :
 * - the signature on a verifies ca's public key
 * - the issuer name on a is the subject name of ca
 * - ca's certificate have the right key usage and Basic Constraints
 * - Authority and Subect Key Identifier (if present) match
 * - Check if certificate is in its validity period.
 * - Check if validity period of a is inside of ca's (not done).
 */
int check_is_issuer(server_rec *sr, X509 *a, X509 *ca)
{
  int i;
  EVP_PKEY *pkey = NULL;
  char subject_name[128], issuer_name[128];
  char buf[128];

  X509_NAME_oneline(X509_get_subject_name(a), subject_name, sizeof (subject_name));
  X509_NAME_oneline(X509_get_subject_name(ca), issuer_name, sizeof (issuer_name));

  /* X509_check_issued checks :
   * 1. Check issuer_name(subject) == subject_name(issuer)
   * 2. If akid(subject) exists check it matches issuer
   * 3. If key_usage(issuer) exists check it supports certificate signing
   */
  if ((i = X509_check_issued(ca, a)) != X509_V_OK) {
    ERR_error_string_n(i, buf, sizeof (buf));
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, sr,
		 "preliminary check of CA %s cert failed: %s", issuer_name, buf);
    return i;
  }
  
  /* ca_check (see details above) checks if certificate is a valid CA.
   * 
   */
#ifdef STRICT_PKIX
  if (ca_check(ca) != 1) {
	ap_log_error(APLOG_MARK, APLOG_ERR, 0, sr, "invalid CA %s", issuer_name);
	return X509_V_ERR_INVALID_CA;
  }
#else
  if (ca_check(ca) == 0) {
	ap_log_error(APLOG_MARK, APLOG_ERR, 0, sr, "invalid CA %s", issuer_name);
	return X509_V_ERR_INVALID_CA;
  }
#endif
  
  /* Check if ca signs cryptographically a */
  if ((pkey = X509_get_pubkey(ca)) == NULL) {
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, sr, "Cannot retrieve public key of CA %s", issuer_name);
    return X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY;
  }
  i = X509_verify(a, pkey);
  EVP_PKEY_free(pkey);
  if (i <= 0) {
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, sr,
		 "signature verification of cert %s against CA %s pubkey failed", subject_name, issuer_name);
    /* Signature verification failed */
    return X509_V_ERR_CERT_SIGNATURE_FAILURE;
  }
  
  /* Check validity period */
  if ((i = X509_cmp_time(X509_get_notBefore(a), NULL)) == 0) {
	ap_log_error(APLOG_MARK, APLOG_ERR, 0, sr,
		     "error in 'not before' field of cert %s", subject_name);
	return X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD;
  } else if (i > 0) {
	  ap_log_error(APLOG_MARK, APLOG_ERR, 0, sr,
		       "cert %s not yet valid", subject_name);
	return X509_V_ERR_CERT_NOT_YET_VALID;
  }
  if ((i = X509_cmp_time(X509_get_notAfter(a), NULL)) == 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, sr,
		     "error in 'not after' field of cert %s", subject_name);
	return X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD;
  } else if (i < 0) {
	ap_log_error(APLOG_MARK, APLOG_ERR, 0, sr,
		     "cert %s has expired", subject_name);
	return X509_V_ERR_CERT_HAS_EXPIRED;
  }
  
  /* Check that certificate validity is inside CA's. This check should
	 be done by the CA. */
  
  return X509_V_OK;
}

/* int is_up_to_date_crl(X509_CRL *crl);
 * 
 * Checks that the CRL is up to date, meaning :
 * - the lastUpdate time is not in the futur
 * - the nextUpdate time is not in the past
 */
int is_up_to_date_crl(server_rec *sr, X509_CRL *crl) {
  int i, ok = X509_V_OK;
  char issuer_name[128];
  
  X509_NAME_oneline(X509_CRL_get_issuer(crl), issuer_name, sizeof (issuer_name));

  i = X509_cmp_time(X509_CRL_get_lastUpdate(crl), NULL);
  if(i == 0) {
	ap_log_error(APLOG_MARK, APLOG_ERR, 0, sr,
		     "error in 'last update' field of CRL issued by %s", issuer_name);
	ok = X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD;
  } else if (i > 0) {
	ap_log_error(APLOG_MARK, APLOG_ERR, 0, sr,
		     "CRL issued by %s not yet valid", issuer_name);
	ok = X509_V_ERR_CRL_NOT_YET_VALID;
  } else {
	if(X509_CRL_get_nextUpdate(crl)) {
	  i = X509_cmp_time(X509_CRL_get_nextUpdate(crl), NULL);
	  if(i == 0) {
		/* There might not be any nextUpdate (it's optional). 
		 * PKIX requires it to be included.
		 */
#ifdef STRICT_PKIX
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, sr,
			     "error in 'next update' field of CRL issued by %s", issuer_name);
		ok = X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD;
#endif
	  } else if(i < 0) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, sr,
			     "CRL issued by %s has expired", issuer_name);
		ok = X509_V_ERR_CRL_HAS_EXPIRED;
	  }
	}
  }

  return ok;
}

/* static int check_crl_issued(X509_CRL *crl, X509 *ca);
 *
 * Checks that the CRL was signed by the certificate ca. Only check
 * that the signature is right (rationale: we're in a "fail-stop"
 * logic, if the system contains CRLs signed by trusted CAs we should
 * not reject them).
 */
static int check_crl_issued(server_rec *sr, X509_CRL *crl, X509 *ca)
{
  EVP_PKEY *pkey = NULL;
  int ok =  X509_V_OK;
  char ca_name[128];
  
  X509_NAME_oneline(X509_get_subject_name(ca), ca_name, sizeof (ca_name));

  if ( ku_reject(ca, KU_CRL_SIGN) )
	  return X509_V_ERR_KEYUSAGE_NO_CRL_SIGN;

  pkey = X509_get_pubkey(ca);

  if(!pkey) {
	  ap_log_error(APLOG_MARK, APLOG_ERR, 0, sr, "Cannot retrieve public key of CA %s", ca_name);
	  ok = X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY;
  } else {
	  /* Verify CRL signature */
	  if(X509_CRL_verify(crl, pkey) <= 0) {
		  ap_log_error(APLOG_MARK, APLOG_ERR, 0, sr,
			       "signature verification of crl against CA %s pubkey failed", ca_name);
   		  ok = X509_V_ERR_CRL_SIGNATURE_FAILURE;
	  }
	  EVP_PKEY_free(pkey);
  }

  return ok;
}

/* STACK_OF(X509) *select_candidates(STACK_OF(X509) *sk, X509_NAME *name)
 *
 * Returns a stack of certificates matching the subject name.
 */
STACK_OF(X509) *select_candidates(STACK_OF(X509) *sk, X509_NAME *name)
{
  STACK_OF(X509) *skx = sk_X509_new_null();
  X509 *tmp;
  int i, num;

  if(sk) {
	num = sk_X509_num(sk);
	for(i = 0; i < num; i++) {
	  tmp = sk_X509_value(sk, i);
	  if(X509_NAME_cmp(X509_get_subject_name(tmp),name) == 0) {
		sk_X509_push(skx, tmp);
	  }
	}
  }
  return skx;
}

int is_valid_cert(X509_STORE_CTX *ctx,
				  STACK_OF(X509) *trusted_CAs,
				  STACK_OF(X509) *untrusted_CAs,
				  STACK_OF(X509_CRL) *crls,
				  X509 *x,
				  int depth)
{
  SSL *ssl = (SSL *)X509_STORE_CTX_get_app_data(ctx);
  conn_rec *conn = (conn_rec *)SSL_get_app_data(ssl);
  server_rec *sr = conn->base_server;
  X509_NAME *xn = X509_get_issuer_name(x);
  X509 *ca = NULL, *tmp = NULL, *crl_signer = NULL;
  X509_CRL* crl = NULL;
  int i, num, rv = X509_V_OK;
  char subject_name[128], issuer_name[128];

  X509_NAME_oneline(X509_get_subject_name(x), subject_name, sizeof (subject_name));
  X509_NAME_oneline(X509_get_issuer_name(x), issuer_name, sizeof (issuer_name));

#if (OPENSSL_VERSION_NUMBER >= 0x0090800fL)
  if(ctx->param->depth < depth) {
#else
  if(ctx->depth < depth) {
#endif /* ! OPENSSL_VERSION_NUMBER */
	ap_log_error(APLOG_MARK, APLOG_ERR, 0, sr,
		     "while checking cert %s: cert chain is too long", subject_name);
	rv = X509_V_ERR_CERT_CHAIN_TOO_LONG;
	goto end;
  }

  /* Search among trusted candidates for the signing CA. The
   * certificate found must be either self-signed (and trusted) or
   * validated.
   */

  num = sk_X509_num(trusted_CAs);
  for (i = 0; (i < num) && (ca == NULL); i++) {
	tmp = sk_X509_value(trusted_CAs, i);
	if(tmp && (X509_NAME_cmp(X509_get_subject_name(tmp), xn) == 0)) {
	  if(check_is_issuer(sr, x, tmp) == X509_V_OK) {
		if(X509_cmp(tmp, x) == 0) {
		  ca = tmp;
		  break;
		} else if(is_valid_cert (ctx, trusted_CAs, NULL, crls, tmp, depth + 1) == X509_V_OK) {
		  ca = tmp;
		}
	  }
	}
  }
    
  /* Now if search failed, now search among untrusted candidates for
   * the signing CA.
   */
  if(ca == NULL) {
	num = sk_X509_num(untrusted_CAs);
	for (i = 0; (i < num) && (ca == NULL); i++) {
	  tmp = sk_X509_value(untrusted_CAs, i);
	  if(tmp && (X509_NAME_cmp(X509_get_subject_name(tmp), xn) == 0)) {
		if(check_is_issuer(sr, x, tmp) == X509_V_OK) {
		  if(X509_cmp(tmp, x) == 0) {
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, sr,
				     "auto signed cert %s is untrusted", issuer_name);
			rv = X509_V_ERR_CERT_UNTRUSTED;
			goto end;
		  } else if(is_valid_cert(ctx, untrusted_CAs, untrusted_CAs, crls, tmp, depth + 1) == X509_V_OK) {
			ca = tmp;
		  }
		}
	  }
	}
  }
  
  /* We didn't find any CA for this certificate.
   */
  if(ca == NULL) {
	ap_log_error(APLOG_MARK, APLOG_ERR, 0, sr, "unable to get issuer cert for %s", subject_name);
	rv = X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT;
	goto end;
  }

  /* Now let's look at CRLs. We look at all CRLs for matching issuer
   * (beginning with the CA that signed the certificate). If the CA
   * didn't sign the CRL we look if CRL signing was delegated to
   * another valid certificate.
   *
   * If the subject name of the certificate is equal to the issuer name
   * don't check it against the CRL, because it would imply an infinite loop
   * on the check of this certificate (because the certificate will be revoked
   * in his own CRL).
   */

  if ( strcmp(subject_name, issuer_name) != 0 ) {
	  num = sk_X509_CRL_num(crls);
	  for (i = 0; i < num ; i++) {
		  crl = sk_X509_CRL_value(crls, i);
		  if(crl && (X509_NAME_cmp(xn, X509_CRL_get_issuer(crl)) == 0)) {
			  X509_REVOKED rtmp;

			  if(check_crl_issued(sr, crl, ca) != X509_V_OK) {
				  X509 *crl_signer = NULL;
				  int j, k;
				  k = sk_X509_num(trusted_CAs);
				  for (j = 0; (j < k) && (crl_signer == NULL); j++) {
					  tmp = sk_X509_value(trusted_CAs, j);
					  if(tmp && (X509_NAME_cmp(X509_get_subject_name(tmp), xn) == 0)) {
						  if(check_crl_issued(sr, crl, tmp) == X509_V_OK) {
							  rv = is_valid_cert(ctx, trusted_CAs, NULL, crls, tmp, depth + 1);
							  if ( rv != X509_V_OK )
								  goto end;
							  crl_signer = tmp;
						  }
					  }
				  }
				  /* We didn't find any signer for this CRL.
				   */
				  if(crl_signer == NULL) {
					  rv = X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT;
					  ap_log_error(APLOG_MARK, APLOG_ERR, 0, sr,
				 "could not find a signer for CRL issued for CA %s", issuer_name);
					  goto end;
				  }
			  }
			  
			  /* Check if the CRL is up to date.
			   */
			  rv = is_up_to_date_crl(sr, crl);
			  if(rv != X509_V_OK)
				  goto end;

			  /* Check if the certificate is in the CRL.
			   */
			  rtmp.serialNumber = X509_get_serialNumber(x);
			  if(sk_X509_REVOKED_find(crl->crl->revoked, &rtmp) != -1) {
				  ap_log_error(APLOG_MARK, APLOG_ERR, 0, sr, "cert %s has been revoked", subject_name);
				  rv = X509_V_ERR_CERT_REVOKED;
				  goto end;
			  }
		  }
	  }
  }

 end:
  ctx->current_cert = x;
  ctx->current_issuer = ca;
  ctx->error_depth = depth;
  ctx->error = rv;

  if (rv == X509_V_OK) {
	sk_X509_push(ctx->chain, x);
	CRYPTO_add(&x->references,1,CRYPTO_LOCK_X509);
  }

  if(ctx->verify_cb) {
	ctx->verify_cb((rv == X509_V_OK) ? 1 : 0, ctx);
  }

  return rv;
}

STACK_OF(X509) *extract_CAs(STACK_OF(X509_OBJECT) *sk)
{
  STACK_OF(X509) *skx = sk_X509_new_null();
  X509_OBJECT *tmp;
  int num, i;

  if(sk) {
	num = sk_X509_OBJECT_num(sk);
	for(i = 0; i < num; i++) {
	  tmp = sk_X509_OBJECT_value(sk, i);
	  if(tmp) {
		if(tmp->type == X509_LU_X509) {
		  sk_X509_push(skx, tmp->data.x509);
		}
	  }
	}
  }
  return skx;
}

STACK_OF(X509_CRL) *extract_CRLs(STACK_OF(X509_OBJECT) *sk)
{
  STACK_OF(X509_CRL) *skx = sk_X509_CRL_new_null();
  X509_OBJECT *tmp;
  int num, i;

  if(sk) {
	num = sk_X509_OBJECT_num(sk);
	for(i = 0; i < num; i++) {
	  tmp = sk_X509_OBJECT_value(sk, i);
	  if(tmp->type == X509_LU_CRL) {
		sk_X509_CRL_push(skx, tmp->data.crl);
	  }
	}
  }
  return skx;
}

void refresh_revocation_store(server_rec *sr, apr_pool_t *pool)
{
  SSLSrvConfigRec *sc = mySrvConfig(sr);
  int reload = 0;
  X509_STORE *old, *new;

  /* Check if CRL file needs reloading */
  if(sc->server->crl_file) {
        apr_finfo_t finfo;

	if ( apr_stat(&finfo, sc->server->crl_file, APR_FINFO_MTIME, pool) != APR_SUCCESS ) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, sr, "Cannot stat %s", sc->server->crl_file);
		return;
	}

	if ( sc->server->crl_file_mtime != finfo.mtime ) {
		reload = 1;
		sc->server->crl_file_mtime = finfo.mtime;
	}
  }
  
  /* Check if CRL directory needs reloading */
  if(sc->server->crl_path) {
	  apr_finfo_t finfo;

	  if ( apr_stat(&finfo, sc->server->crl_path, APR_FINFO_MTIME, pool) != APR_SUCCESS ) {
		  ap_log_error(APLOG_MARK, APLOG_ERR, 0, sr, "Cannot stat %s", sc->server->crl_path);
		  return;
	  }

	  if ( sc->server->crl_path_mtime != finfo.mtime ) {
		  reload = 1;
		  sc->server->crl_path_mtime = finfo.mtime;
	  }
  }
  
  /* Do the reloading */
  if(reload) {
	apr_time_t last_changed, now;
	
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, sr, "Reloading CRLs");
	/*
	 * If a CRL update + a ssl_verify function call + a new CRL update happen at
	 * the same time (I mean, at the same seconds count since epoch), the second
	 * CRL update will not be detected by the stat crl_file/crl_path check.
	 * That is why we sleep until the next second since epoch after a CRL update has
	 * been detected, to be sure we have caught all CRL update that happen in the
	 * given epoch time.
	 */
	last_changed = (sc->server->crl_file_mtime > sc->server->crl_path_mtime) ? \
		sc->server->crl_file_mtime : sc->server->crl_path_mtime;
	now = apr_time_now();
	if ( apr_time_sec(last_changed) == apr_time_sec(now) )
		apr_sleep(apr_time_from_sec(apr_time_sec(last_changed) + 1) - now);
	new = SSL_X509_STORE_create ((char *) sc->server->crl_file, (char *) sc->server->crl_path);
	if (new == NULL) {
	  ssl_log_ssl_error(APLOG_MARK, APLOG_INFO, sr);
	  ssl_die();
	}
	/* Replacing old Revocation Store with new one atomically. */
	old = sc->server->crl;
	sc->server->crl = new;
	X509_STORE_free(old);
  }
}

int ssl_verify(X509_STORE_CTX *ctx, void *dummy)
{
  STACK_OF(X509) *trusted_CAs = NULL;
  STACK_OF(X509) *untrusted_CAs = ctx->untrusted;
  STACK_OF(X509_CRL) *crls;
  SSL *ssl = (SSL *)X509_STORE_CTX_get_app_data(ctx);
  conn_rec *conn = (conn_rec *)SSL_get_app_data(ssl);
  SSLSrvConfigRec *sc = mySrvConfig(conn->base_server);
  server_rec *s = conn->base_server;
  int ok;

  ssl_mutex_on(s);

  trusted_CAs = extract_CAs(sc->server->ssl_ctx->cert_store->objs);
 
  if(sc->server->crl) {
	refresh_revocation_store(s, conn->pool);
	crls = extract_CRLs(sc->server->crl->objs);
  } else {
	crls = sk_X509_CRL_new_null();
  }

  /* Starting the chain
   */
  if (ctx->chain == NULL) {
	ctx->chain = sk_X509_new_null();
  }
  
  ok = is_valid_cert(ctx, trusted_CAs, untrusted_CAs, crls, ctx->cert, 0);
 
  sk_X509_free(trusted_CAs);

  ssl_mutex_off(s);

  return (ok == X509_V_OK) ? 1 : 0;
}

int ssl_verify_error(int ok, X509_STORE_CTX *ctx)
{
  SSL *ssl;
  conn_rec *conn;
  server_rec *s;
  request_rec *r;
  SSLSrvConfigRec *sc;
  SSLDirConfigRec *dc;
  SSLConnRec *sslconn;
  X509 *xs;
  int errnum;
  int errdepth;
  char *cp;
  char *cp2;

  /*
   * Get Apache context back through OpenSSL context
   */
  ssl  = (SSL *)X509_STORE_CTX_get_app_data(ctx);
  conn = (conn_rec *)SSL_get_app_data(ssl);
  sslconn = myConnConfig(conn);
  
  r    = (request_rec *) SSL_get_app_data2(ssl);
  s    = conn->base_server;
  sc   = mySrvConfig(s);
  dc   = (r != NULL ? myDirConfig(r) : NULL);

  /*
   * Get verify ingredients
   */
  xs       = X509_STORE_CTX_get_current_cert(ctx);
  errnum   = X509_STORE_CTX_get_error(ctx);
  errdepth = X509_STORE_CTX_get_error_depth(ctx);

  /*
   * Log verification information
   */
  cp  = X509_NAME_oneline(X509_get_subject_name(xs), NULL, 0);
  cp2 = X509_NAME_oneline(X509_get_issuer_name(xs),  NULL, 0);
  ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
		  "ASIP Sante : Certificate Verification: depth: %d, subject: %s, issuer: %s",
		  errdepth, cp != NULL ? cp : "-unknown-",
		  cp2 != NULL ? cp2 : "-unknown");
  if (cp)
	free(cp);
  if (cp2)
	free(cp2);
  
  if (ok == 0) {
        ssl_log_ssl_error(APLOG_MARK, APLOG_ERR, s);
	sslconn->client_dn = NULL;
	sslconn->verify_error = X509_verify_cert_error_string(errnum);
  }
  
  return ok;
}
