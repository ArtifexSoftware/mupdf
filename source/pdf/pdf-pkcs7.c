#include "mupdf/fitz.h"
#include "mupdf/pdf.h"
#include "../fitz/fitz-imp.h"

#include <string.h>

#ifdef HAVE_LIBCRYPTO

/* Generated from resources/certs/AdobeCA.p7c */
static const char AdobeCA_p7c[] = {
48,130,4,208,6,9,42,134,72,134,247,13,1,7,2,160,130,4,193,48,130,4,189,2,
1,1,49,0,48,11,6,9,42,134,72,134,247,13,1,7,1,160,130,4,165,48,130,4,161,
48,130,3,137,160,3,2,1,2,2,4,62,28,189,40,48,13,6,9,42,134,72,134,247,13,
1,1,5,5,0,48,105,49,11,48,9,6,3,85,4,6,19,2,85,83,49,35,48,33,6,3,85,4,10,
19,26,65,100,111,98,101,32,83,121,115,116,101,109,115,32,73,110,99,111,114,
112,111,114,97,116,101,100,49,29,48,27,6,3,85,4,11,19,20,65,100,111,98,101,
32,84,114,117,115,116,32,83,101,114,118,105,99,101,115,49,22,48,20,6,3,85,
4,3,19,13,65,100,111,98,101,32,82,111,111,116,32,67,65,48,30,23,13,48,51,
48,49,48,56,50,51,51,55,50,51,90,23,13,50,51,48,49,48,57,48,48,48,55,50,51,
90,48,105,49,11,48,9,6,3,85,4,6,19,2,85,83,49,35,48,33,6,3,85,4,10,19,26,
65,100,111,98,101,32,83,121,115,116,101,109,115,32,73,110,99,111,114,112,
111,114,97,116,101,100,49,29,48,27,6,3,85,4,11,19,20,65,100,111,98,101,32,
84,114,117,115,116,32,83,101,114,118,105,99,101,115,49,22,48,20,6,3,85,4,
3,19,13,65,100,111,98,101,32,82,111,111,116,32,67,65,48,130,1,34,48,13,6,
9,42,134,72,134,247,13,1,1,1,5,0,3,130,1,15,0,48,130,1,10,2,130,1,1,0,204,
79,84,132,247,167,162,231,51,83,127,63,156,18,136,107,44,153,71,103,126,15,
30,185,173,20,136,249,195,16,216,29,240,240,213,159,105,10,47,89,53,176,204,
108,169,76,156,21,160,159,206,32,191,160,207,84,226,224,32,102,69,63,57,134,
56,126,156,196,142,7,34,198,36,246,1,18,176,53,223,85,234,105,144,176,219,
133,55,30,226,78,7,178,66,161,106,19,105,160,102,234,128,145,17,89,42,155,
8,121,90,32,68,45,201,189,115,56,139,60,47,224,67,27,93,179,11,240,175,53,
26,41,254,239,166,146,221,129,76,157,61,89,142,173,49,60,64,126,155,145,54,
6,252,226,92,141,209,141,38,213,92,69,207,175,101,63,177,170,210,98,150,244,
168,56,234,186,96,66,244,244,28,74,53,21,206,248,78,34,86,15,149,24,197,248,
150,159,159,251,176,183,120,37,233,128,107,189,214,10,240,198,116,148,157,
243,15,80,219,154,119,206,75,112,131,35,141,160,202,120,32,68,92,60,84,100,
241,234,162,48,25,159,234,76,6,77,6,120,75,94,146,223,34,210,201,103,179,
122,210,1,2,3,1,0,1,163,130,1,79,48,130,1,75,48,17,6,9,96,134,72,1,134,248,
66,1,1,4,4,3,2,0,7,48,129,142,6,3,85,29,31,4,129,134,48,129,131,48,129,128,
160,126,160,124,164,122,48,120,49,11,48,9,6,3,85,4,6,19,2,85,83,49,35,48,
33,6,3,85,4,10,19,26,65,100,111,98,101,32,83,121,115,116,101,109,115,32,73,
110,99,111,114,112,111,114,97,116,101,100,49,29,48,27,6,3,85,4,11,19,20,65,
100,111,98,101,32,84,114,117,115,116,32,83,101,114,118,105,99,101,115,49,
22,48,20,6,3,85,4,3,19,13,65,100,111,98,101,32,82,111,111,116,32,67,65,49,
13,48,11,6,3,85,4,3,19,4,67,82,76,49,48,43,6,3,85,29,16,4,36,48,34,128,15,
50,48,48,51,48,49,48,56,50,51,51,55,50,51,90,129,15,50,48,50,51,48,49,48,
57,48,48,48,55,50,51,90,48,11,6,3,85,29,15,4,4,3,2,1,6,48,31,6,3,85,29,35,
4,24,48,22,128,20,130,183,56,74,147,170,155,16,239,128,187,217,84,226,241,
15,251,128,156,222,48,29,6,3,85,29,14,4,22,4,20,130,183,56,74,147,170,155,
16,239,128,187,217,84,226,241,15,251,128,156,222,48,12,6,3,85,29,19,4,5,48,
3,1,1,255,48,29,6,9,42,134,72,134,246,125,7,65,0,4,16,48,14,27,8,86,54,46,
48,58,52,46,48,3,2,4,144,48,13,6,9,42,134,72,134,247,13,1,1,5,5,0,3,130,1,
1,0,50,218,159,67,117,193,250,111,201,111,219,171,29,54,55,62,188,97,25,54,
183,2,60,29,35,89,152,108,158,238,77,133,231,84,200,32,31,167,212,187,226,
191,0,119,125,36,107,112,47,92,193,58,118,73,181,211,224,35,132,42,113,106,
34,243,193,39,41,152,21,246,53,144,228,4,76,195,141,188,159,97,28,231,253,
36,140,209,68,67,140,22,186,155,77,165,212,53,47,188,17,206,189,247,81,55,
141,159,144,228,20,241,24,63,190,233,89,18,53,249,51,146,243,158,224,213,
107,154,113,155,153,75,200,113,195,225,177,97,9,196,229,250,145,240,66,58,
55,125,52,249,114,232,205,170,98,28,33,233,213,244,130,16,227,123,5,182,45,
104,86,11,126,126,146,44,111,77,114,130,12,237,86,116,178,157,185,171,45,
43,29,16,95,219,39,117,112,143,253,29,215,226,2,160,121,229,28,229,255,175,
100,64,81,45,158,155,71,219,66,165,124,31,194,166,72,176,215,190,146,105,
77,164,246,41,87,197,120,17,24,220,135,81,202,19,178,98,157,79,43,50,189,
49,165,193,250,82,171,5,136,200,49,0
};

#include "openssl/err.h"
#include "openssl/bio.h"
#include "openssl/asn1.h"
#include "openssl/x509.h"
#include "openssl/x509v3.h"
#include "openssl/err.h"
#include "openssl/objects.h"
#include "openssl/pem.h"
#include "openssl/pkcs7.h"
#include "openssl/pkcs12.h"
#include "openssl/opensslv.h"

#ifndef OPENSSL_VERSION_NUMBER
#warning detect version of openssl at compile time
#endif

typedef struct
{
	fz_context *ctx;
	fz_stream *stm;
} BIO_stream_data;

static int stream_read(BIO *b, char *buf, int size)
{
	BIO_stream_data *data = (BIO_stream_data *)BIO_get_data(b);
	return fz_read(data->ctx, data->stm, (unsigned char *) buf, size);
}

static long stream_ctrl(BIO *b, int cmd, long arg1, void *arg2)
{
	BIO_stream_data *data = (BIO_stream_data *)BIO_get_data(b);
	switch (cmd)
	{
	case BIO_C_FILE_SEEK:
		fz_seek(data->ctx, data->stm, arg1, SEEK_SET);
		return 0;
	default:
		return 1;
	}
}

static int stream_new(BIO *b)
{
	BIO_stream_data *data = (BIO_stream_data *)malloc(sizeof(BIO_stream_data));
	if (!data)
		return 0;

	data->ctx = NULL;
	data->stm = NULL;

	BIO_set_init(b, 1);
	BIO_set_data(b, data);
	BIO_clear_flags(b, INT_MAX);

	return 1;
}

static int stream_free(BIO *b)
{
	if (b == NULL)
		return 0;

	free(BIO_get_data(b));
	BIO_set_data(b, NULL);
	BIO_set_init(b, 0);
	BIO_clear_flags(b, INT_MAX);

	return 1;
}

static long stream_callback_ctrl(BIO *b, int cmd, bio_info_cb *fp)
{
	return 1;
}

static BIO *BIO_new_stream(fz_context *ctx, fz_stream *stm)
{
	static BIO_METHOD *methods = NULL;
	BIO *bio;
	BIO_stream_data *data;

	if (!methods)
	{
		methods = BIO_meth_new(BIO_TYPE_NONE, "segment reader");
		if (!methods)
			return NULL;

		BIO_meth_set_read(methods, stream_read);
		BIO_meth_set_ctrl(methods, stream_ctrl);
		BIO_meth_set_create(methods, stream_new);
		BIO_meth_set_destroy(methods, stream_free);
		BIO_meth_set_callback_ctrl(methods, stream_callback_ctrl);
	}

	bio = BIO_new(methods);
	data = BIO_get_data(bio);
	data->ctx = ctx;
	data->stm = stm;

	return bio;
}

enum
{
	SEG_START = 0,
	SEG_SIZE = 1
};

typedef struct bsegs_struct
{
	int (*seg)[2];
	int nsegs;
	int current_seg;
	int seg_pos;
} BIO_SEGS_CTX;

static int bsegs_read(BIO *b, char *buf, int size)
{
	BIO_SEGS_CTX *ctx = (BIO_SEGS_CTX *) BIO_get_data(b);
	int read = 0;

	while (size > 0 && ctx->current_seg < ctx->nsegs)
	{
		int nb = ctx->seg[ctx->current_seg][SEG_SIZE] - ctx->seg_pos;

		if (nb > size)
			nb = size;

		if (nb > 0)
		{
			if (ctx->seg_pos == 0)
			{
				if (BIO_seek(BIO_next(b), ctx->seg[ctx->current_seg][SEG_START]) < 0)
					return read;
			}

			nb = BIO_read(BIO_next(b), buf, nb);
			if (nb <= 0)
				return read;

			ctx->seg_pos += nb;
			read += nb;
			buf += nb;
			size -= nb;
		}
		else
		{
			ctx->current_seg++;

			if (ctx->current_seg < ctx->nsegs)
				ctx->seg_pos = 0;
		}
	}

	return read;
}

static long bsegs_ctrl(BIO *b, int cmd, long arg1, void *arg2)
{
	return BIO_ctrl(BIO_next(b), cmd, arg1, arg2);
}

static int bsegs_new(BIO *b)
{
	BIO_SEGS_CTX *ctx;

	ctx = (BIO_SEGS_CTX *)malloc(sizeof(BIO_SEGS_CTX));
	if (ctx == NULL)
		return 0;

	ctx->current_seg = 0;
	ctx->seg_pos = 0;
	ctx->seg = NULL;
	ctx->nsegs = 0;

	BIO_set_init(b, 1);
	BIO_set_data(b, ctx);
	BIO_clear_flags(b, INT_MAX);

	return 1;
}

static int bsegs_free(BIO *b)
{
	if (b == NULL)
		return 0;

	free(BIO_get_data(b));
	BIO_set_data(b, NULL);
	BIO_set_init(b, 0);
	BIO_clear_flags(b, INT_MAX);

	return 1;
}

static long bsegs_callback_ctrl(BIO *b, int cmd, bio_info_cb *fp)
{
	return BIO_callback_ctrl(BIO_next(b), cmd, fp);
}

static BIO_METHOD *methods_bsegs = NULL;

static BIO_METHOD *BIO_f_segments(void)
{
	if (methods_bsegs)
		return methods_bsegs;

	methods_bsegs = BIO_meth_new(BIO_TYPE_NONE, "segment reader");
	if (!methods_bsegs)
		return NULL;

	if (!BIO_meth_set_read(methods_bsegs, bsegs_read) ||
			!BIO_meth_set_ctrl(methods_bsegs, bsegs_ctrl) ||
			!BIO_meth_set_create(methods_bsegs, bsegs_new) ||
			!BIO_meth_set_destroy(methods_bsegs, bsegs_free) ||
			!BIO_meth_set_callback_ctrl(methods_bsegs, bsegs_callback_ctrl))

	{
		BIO_meth_free(methods_bsegs);
		methods_bsegs = NULL;
	}

	return methods_bsegs;
}

static void BIO_set_segments(BIO *b, int (*seg)[2], int nsegs)
{
	BIO_SEGS_CTX *ctx = (BIO_SEGS_CTX *) BIO_get_data(b);

	ctx->seg = seg;
	ctx->nsegs = nsegs;
}

static int verify_callback(int ok, X509_STORE_CTX *ctx)
{
	int err, depth;

	err = X509_STORE_CTX_get_error(ctx);
	depth = X509_STORE_CTX_get_error_depth(ctx);

	if (!ok && depth >= 6)
	{
		X509_STORE_CTX_set_error(ctx, X509_V_ERR_CERT_CHAIN_TOO_LONG);
	}

	switch (err)
	{
	case X509_V_ERR_INVALID_PURPOSE:
	case X509_V_ERR_CERT_HAS_EXPIRED:
	case X509_V_ERR_KEYUSAGE_NO_CERTSIGN:
		X509_STORE_CTX_set_error(ctx, X509_V_OK);
		ok = 1;
		break;

	default:
		break;
	}

	return ok;
}

/* Get the certificates from a PKCS7 object */
static STACK_OF(X509) *pk7_certs(PKCS7 *pk7)
{
	if (pk7 == NULL || pk7->d.ptr == NULL)
		return NULL;

	if (PKCS7_type_is_signed(pk7))
		return pk7->d.sign->cert;
	else if (PKCS7_type_is_signedAndEnveloped(pk7))
		return pk7->d.signed_and_enveloped->cert;
	else
		return NULL;
}

/* Get the signing certificate from a PKCS7 object */
static X509 *pk7_signer(STACK_OF(X509) *certs, PKCS7_SIGNER_INFO *si)
{
	PKCS7_ISSUER_AND_SERIAL *ias = si->issuer_and_serial;
	if (certs == NULL)
		return NULL;

	return X509_find_by_issuer_and_serial(certs, ias->issuer, ias->serial);
}

static int pk7_verify_sig(PKCS7 *p7, BIO *detached, char *ebuf, int ebufsize)
{
	BIO *p7bio=NULL;
	char readbuf[1024*4];
	int res = 1;
	int i;
	STACK_OF(PKCS7_SIGNER_INFO) *sk;

	ebuf[0] = 0;

	ERR_clear_error();

	p7bio = PKCS7_dataInit(p7, detached);
	if (!p7bio)
		goto exit;


	/* We now have to 'read' from p7bio to calculate digests etc. */
	while (BIO_read(p7bio, readbuf, sizeof(readbuf)) > 0)
		;

	/* We can now verify signatures */
	sk = PKCS7_get_signer_info(p7);
	if (sk == NULL)
	{
		/* there are no signatures on this data */
		res = 0;
		fz_strlcpy(ebuf, "No signatures", ebufsize);
		goto exit;
	}

	for (i=0; i<sk_PKCS7_SIGNER_INFO_num(sk); i++)
	{
		int rc;
		PKCS7_SIGNER_INFO *si = sk_PKCS7_SIGNER_INFO_value(sk, i);
		X509 *x509 = pk7_signer(pk7_certs(p7), si);

		/* were we able to find the cert in passed to us */
		if (x509 == NULL)
		{
			res = 0;
			fz_strlcpy(ebuf, "No signatures", ebufsize);
			goto exit;
		}

		rc = PKCS7_signatureVerify(p7bio, p7, si, x509);
		if (rc <= 0)
		{
			ERR_error_string_n(ERR_get_error(), ebuf, ebufsize);
			res = 0;
			goto exit;
		}
	}

exit:
	ERR_free_strings();

	return res;
}

static int pk7_verify_cert(X509_STORE *cert_store, PKCS7 *p7, char *ebuf, int ebufsize)
{
	int res = 1;
	int i;
	STACK_OF(PKCS7_SIGNER_INFO) *sk;
	X509_STORE_CTX *ctx;

	ebuf[0] = 0;

	ctx = X509_STORE_CTX_new();

	ERR_clear_error();

	X509_STORE_set_verify_cb_func(cert_store, verify_callback);

	/* We can now verify signatures */
	sk = PKCS7_get_signer_info(p7);
	if (sk == NULL)
	{
		/* there are no signatures on this data */
		res = 0;
		fz_strlcpy(ebuf, "No signatures", ebufsize);
		goto exit;
	}

	for (i=0; i<sk_PKCS7_SIGNER_INFO_num(sk); i++)
	{
		int ctx_err;
		PKCS7_SIGNER_INFO *si = sk_PKCS7_SIGNER_INFO_value(sk, i);
		STACK_OF(X509) *certs = pk7_certs(p7);
		X509 *cert = pk7_signer(certs, si);
		if (cert == NULL)
		{
			res = 0;
			fz_strlcpy(ebuf, "Certificate missing", ebufsize);
			goto exit;
		}

		/* Acrobat reader creates self-signed certificates that don't list
		 * certificate signing within the key usage parameters. openssl does
		 * not recognise those as self signed. We work around this by removing
		 * the key usage parameters before the verification check */
		{
			int i = X509_get_ext_by_NID(cert, NID_key_usage, -1);
			if (i >= 0)
			{
				X509_EXTENSION *ext = X509_get_ext(cert, i);
				X509_delete_ext(cert, i);
				X509_EXTENSION_free(ext);
			}
		}

		if (!X509_STORE_CTX_init(ctx, cert_store, cert, certs))
		{
			res = 0;
			PKCS7err(PKCS7_F_PKCS7_DATAVERIFY, ERR_R_X509_LIB);
			goto exit;
		}

		X509_STORE_CTX_set_purpose(ctx, X509_PURPOSE_SMIME_SIGN);

		X509_verify_cert(ctx);
		X509_STORE_CTX_cleanup(ctx);
		ctx_err = X509_STORE_CTX_get_error(ctx);
		if (ctx_err != X509_V_OK)
		{
			int used;
			fz_snprintf(ebuf, ebufsize, "%s(%d): ", X509_verify_cert_error_string(ctx_err), ctx_err);
			used = strlen(ebuf);
			X509_NAME_oneline(X509_get_subject_name(cert), ebuf + used, ebufsize - used);

			res = 0;
			goto exit;
		}
	}

exit:
	X509_STORE_CTX_cleanup(ctx);
	ERR_free_strings();

	return res;
}

static int verify_sig(fz_context *ctx, fz_stream *stm, char *sig, int sig_len, int (*byte_range)[2], int byte_range_len, char *ebuf, int ebufsize)
{
	PKCS7 *pk7sig = NULL;
	BIO *bsig = NULL;
	BIO *bdata = NULL;
	BIO *bsegs = NULL;
	STACK_OF(X509) *certs = NULL;
	int res = 0;

	bsig = BIO_new_mem_buf(sig, sig_len);
	pk7sig = d2i_PKCS7_bio(bsig, NULL);
	if (pk7sig == NULL)
		goto exit;

	bdata = BIO_new_stream(ctx, stm);
	if (bdata == NULL)
		goto exit;

	bsegs = BIO_new(BIO_f_segments());
	if (bsegs == NULL)
		goto exit;

	BIO_set_next(bsegs, bdata);
	BIO_set_segments(bsegs, byte_range, byte_range_len);

	res = pk7_verify_sig(pk7sig, bsegs, ebuf, ebufsize);

exit:
	BIO_free(bsig);
	BIO_free(bdata);
	BIO_free(bsegs);
	PKCS7_free(pk7sig);

	return res;
}

static int verify_cert(fz_context *ctx, char *sig, int sig_len, char *ebuf, int ebufsize)
{
	PKCS7 *pk7sig = NULL;
	PKCS7 *pk7cert = NULL;
	X509_STORE *st = NULL;
	BIO *bsig = NULL;
	BIO *bcert = NULL;
	STACK_OF(X509) *certs = NULL;
	int res = 0;

	bsig = BIO_new_mem_buf(sig, sig_len);
	pk7sig = d2i_PKCS7_bio(bsig, NULL);
	if (pk7sig == NULL)
		goto exit;

	/* Find the certificates in the pk7 file */
	bcert = BIO_new_mem_buf((void*)AdobeCA_p7c, sizeof AdobeCA_p7c);
	pk7cert = d2i_PKCS7_bio(bcert, NULL);
	if (pk7cert == NULL)
		goto exit;

	certs = pk7_certs(pk7cert);

	st = X509_STORE_new();
	if (st == NULL)
		goto exit;

	/* Add the certificates to the store */
	if (certs != NULL)
	{
		int i, n = sk_X509_num(certs);

		for (i = 0; i < n; i++)
		{
			X509 *c = sk_X509_value(certs, i);
			X509_STORE_add_cert(st, c);
		}
	}

	res = pk7_verify_cert(st, pk7sig, ebuf, ebufsize);

exit:
	BIO_free(bsig);
	BIO_free(bcert);
	PKCS7_free(pk7sig);
	PKCS7_free(pk7cert);
	X509_STORE_free(st);

	return res;
}

typedef struct pdf_designated_name_openssl_s
{
	pdf_designated_name base;
	char buf[8192];
} pdf_designated_name_openssl;

struct pdf_signer_s
{
	int refs;
	X509 *x509;
	EVP_PKEY *pkey;
};

void pdf_drop_designated_name(fz_context *ctx, pdf_designated_name *dn)
{
	fz_free(ctx, dn);
}

static void add_from_bags(X509 **pX509, EVP_PKEY **pPkey, const STACK_OF(PKCS12_SAFEBAG) *bags, const char *pw);

static void add_from_bag(X509 **pX509, EVP_PKEY **pPkey, PKCS12_SAFEBAG *bag, const char *pw)
{
	EVP_PKEY *pkey = NULL;
	X509 *x509 = NULL;
	switch (M_PKCS12_bag_type(bag))
	{
	case NID_keyBag:
		{
			const PKCS8_PRIV_KEY_INFO *p8 = PKCS12_SAFEBAG_get0_p8inf(bag);
			pkey = EVP_PKCS82PKEY(p8);
		}
		break;

	case NID_pkcs8ShroudedKeyBag:
		{
			PKCS8_PRIV_KEY_INFO *p8 = PKCS12_decrypt_skey(bag, pw, (int)strlen(pw));
			if (p8)
			{
				pkey = EVP_PKCS82PKEY(p8);
				PKCS8_PRIV_KEY_INFO_free(p8);
			}
		}
		break;

	case NID_certBag:
		if (M_PKCS12_cert_bag_type(bag) == NID_x509Certificate)
			x509 = PKCS12_certbag2x509(bag);
		break;

	case NID_safeContentsBag:
		add_from_bags(pX509, pPkey, PKCS12_SAFEBAG_get0_safes(bag), pw);
		break;
	}

	if (pkey)
	{
		if (!*pPkey)
			*pPkey = pkey;
		else
			EVP_PKEY_free(pkey);
	}

	if (x509)
	{
		if (!*pX509)
			*pX509 = x509;
		else
			X509_free(x509);
	}
}

static void add_from_bags(X509 **pX509, EVP_PKEY **pPkey, const STACK_OF(PKCS12_SAFEBAG) *bags, const char *pw)
{
	int i;

	for (i = 0; i < sk_PKCS12_SAFEBAG_num(bags); i++)
		add_from_bag(pX509, pPkey, sk_PKCS12_SAFEBAG_value(bags, i), pw);
}

pdf_signer *pdf_read_pfx(fz_context *ctx, const char *pfile, const char *pw)
{
	BIO *pfxbio = NULL;
	PKCS12 *p12 = NULL;
	STACK_OF(PKCS7) *asafes;
	pdf_signer *signer = NULL;
	int i;

	fz_var(pfxbio);
	fz_var(p12);
	fz_var(signer);
	fz_try(ctx)
	{
		signer = fz_malloc_struct(ctx, pdf_signer);
		signer->refs = 1;

		OpenSSL_add_all_algorithms();

		EVP_add_digest(EVP_md5());
		EVP_add_digest(EVP_sha1());

		ERR_load_crypto_strings();

		ERR_clear_error();

		pfxbio = BIO_new_file(pfile, "rb");
		if (pfxbio == NULL)
			fz_throw(ctx, FZ_ERROR_GENERIC, "Can't open pfx file: %s", pfile);

		p12 = d2i_PKCS12_bio(pfxbio, NULL);
		if (p12 == NULL)
			fz_throw(ctx, FZ_ERROR_GENERIC, "Invalid pfx file: %s", pfile);

		asafes = PKCS12_unpack_authsafes(p12);
		if (asafes == NULL)
			fz_throw(ctx, FZ_ERROR_GENERIC, "Invalid pfx file: %s", pfile);

		/* Nothing in this for loop can fz_throw */
		for (i = 0; i < sk_PKCS7_num(asafes); i++)
		{
			PKCS7 *p7;
			STACK_OF(PKCS12_SAFEBAG) *bags;
			int bagnid;

			p7 = sk_PKCS7_value(asafes, i);
			bagnid = OBJ_obj2nid(p7->type);
			switch (bagnid)
			{
			case NID_pkcs7_data:
				bags = PKCS12_unpack_p7data(p7);
				break;
			case NID_pkcs7_encrypted:
				bags = PKCS12_unpack_p7encdata(p7, pw, (int)strlen(pw));
				break;
			default:
				continue;
			}

			if (bags)
			{
				add_from_bags(&signer->x509, &signer->pkey, bags, pw);
				sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
			}
		}
		sk_PKCS7_pop_free (asafes, PKCS7_free);

		if (signer->pkey == NULL)
			fz_throw(ctx, FZ_ERROR_GENERIC, "Failed to obtain public key");

		if (signer->x509 == NULL)
			fz_throw(ctx, FZ_ERROR_GENERIC, "Failed to obtain certificate");
	}
	fz_always(ctx)
	{
		BIO_free(pfxbio);
		PKCS12_free(p12);
	}
	fz_catch(ctx)
	{
		pdf_drop_signer(ctx, signer);
		fz_rethrow(ctx);
	}

	return signer;
}

pdf_signer *pdf_keep_signer(fz_context *ctx, pdf_signer *signer)
{
	return fz_keep_imp(ctx, signer, &signer->refs);
}

void pdf_drop_signer(fz_context *ctx, pdf_signer *signer)
{
	if (fz_drop_imp(ctx, signer, &signer->refs))
	{
		X509_free(signer->x509);
		EVP_PKEY_free(signer->pkey);
		fz_free(ctx, signer);
	}
}

pdf_designated_name *pdf_signer_designated_name(fz_context *ctx, pdf_signer *signer)
{
	pdf_designated_name_openssl *dn = fz_malloc_struct(ctx, pdf_designated_name_openssl);
	char *p;

	X509_NAME_oneline(X509_get_subject_name(signer->x509), dn->buf, sizeof(dn->buf));
	p = strstr(dn->buf, "/CN=");
	if (p) dn->base.cn = p+4;
	p = strstr(dn->buf, "/O=");
	if (p) dn->base.o = p+3;
	p = strstr(dn->buf, "/OU=");
	if (p) dn->base.ou = p+4;
	p = strstr(dn->buf, "/emailAddress=");
	if (p) dn->base.email = p+14;
	p = strstr(dn->buf, "/C=");
	if (p) dn->base.c = p+3;

	for (p = dn->buf; *p; p++)
		if (*p == '/')
			*p = 0;

	return (pdf_designated_name *)dn;
}

void pdf_write_digest(fz_context *ctx, fz_output *out, pdf_obj *byte_range, int digest_offset, int digest_length, pdf_signer *signer)
{
	fz_stream *in = NULL;
	BIO *bdata = NULL;
	BIO *bsegs = NULL;
	BIO *bp7in = NULL;
	BIO *bp7 = NULL;
	PKCS7 *p7 = NULL;
	PKCS7_SIGNER_INFO *si;

	int (*brange)[2] = NULL;
	int brange_len = pdf_array_len(ctx, byte_range)/2;

	fz_var(in);
	fz_var(bdata);
	fz_var(bsegs);
	fz_var(bp7in);
	fz_var(bp7);
	fz_var(p7);

	fz_try(ctx)
	{
		unsigned char *p7_ptr;
		int p7_len;
		int i;

		in = fz_stream_from_output(ctx, out);

		brange = fz_calloc(ctx, brange_len, sizeof(*brange));
		for (i = 0; i < brange_len; i++)
		{
			brange[i][0] = pdf_to_int(ctx, pdf_array_get(ctx, byte_range, 2*i));
			brange[i][1] = pdf_to_int(ctx, pdf_array_get(ctx, byte_range, 2*i+1));
		}

		bdata = BIO_new_stream(ctx, in);
		if (bdata == NULL)
			fz_throw(ctx, FZ_ERROR_GENERIC, "Failed to create file BIO");

		bsegs = BIO_new(BIO_f_segments());
		if (bsegs == NULL)
			fz_throw(ctx, FZ_ERROR_GENERIC, "Failed to create segment filter");

		BIO_set_next(bsegs, bdata);
		BIO_set_segments(bsegs, brange, brange_len);

		p7 = PKCS7_new();
		if (p7 == NULL)
			fz_throw(ctx, FZ_ERROR_GENERIC, "Failed to create p7 object");

		PKCS7_set_type(p7, NID_pkcs7_signed);
		si = PKCS7_add_signature(p7, signer->x509, signer->pkey, EVP_sha1());
		if (si == NULL)
			fz_throw(ctx, FZ_ERROR_GENERIC, "Failed to add signature");

		PKCS7_add_signed_attribute(si, NID_pkcs9_contentType, V_ASN1_OBJECT, OBJ_nid2obj(NID_pkcs7_data));
		PKCS7_add_certificate(p7, signer->x509);

		PKCS7_content_new(p7, NID_pkcs7_data);
		PKCS7_set_detached(p7, 1);

		bp7in = PKCS7_dataInit(p7, NULL);
		if (bp7in == NULL)
			fz_throw(ctx, FZ_ERROR_GENERIC, "Failed to write to digest");

		while(1)
		{
			char buf[4096];
			int n = BIO_read(bsegs, buf, sizeof(buf));
			if (n <= 0)
				break;
			BIO_write(bp7in, buf, n);
		}

		if (!PKCS7_dataFinal(p7, bp7in))
			fz_throw(ctx, FZ_ERROR_GENERIC, "Failed to write to digest");

		BIO_free(bsegs);
		bsegs = NULL;
		BIO_free(bdata);
		bdata = NULL;
		fz_drop_stream(ctx, in);
		in = NULL;

		bp7 = BIO_new(BIO_s_mem());
		if (bp7 == NULL || !i2d_PKCS7_bio(bp7, p7))
			fz_throw(ctx, FZ_ERROR_GENERIC, "Failed to create memory buffer for digest");

		p7_len = BIO_get_mem_data(bp7, &p7_ptr);
		if (p7_len*2 + 2 > digest_length)
			fz_throw(ctx, FZ_ERROR_GENERIC, "Insufficient space for digest");

		fz_seek_output(ctx, out, digest_offset+1, SEEK_SET);

		for (i = 0; i < p7_len; i++)
			fz_write_printf(ctx, out, "%02x", p7_ptr[i]);
	}
	fz_always(ctx)
	{
		fz_drop_stream(ctx, in);
		PKCS7_free(p7);
		BIO_free(bsegs);
		BIO_free(bdata);
		BIO_free(bp7in);
		BIO_free(bp7);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}
}

int pdf_check_signature(fz_context *ctx, pdf_document *doc, pdf_widget *widget, char *ebuf, int ebufsize)
{
	int (*byte_range)[2] = NULL;
	int byte_range_len;
	char *contents = NULL;
	int contents_len;
	int res = 0;

	if (pdf_xref_obj_is_unsaved_signature(doc, ((pdf_annot *)widget)->obj))
	{
		fz_strlcpy(ebuf, "Signed but document yet to be saved", ebufsize);
		if (ebufsize > 0)
			ebuf[ebufsize-1] = 0;
		return 0;
	}

	fz_var(byte_range);
	fz_var(res);
	fz_try(ctx)
	{
		byte_range_len = pdf_signature_widget_byte_range(ctx, doc, widget, NULL);
		if (byte_range_len)
		{
			byte_range = fz_calloc(ctx, byte_range_len, sizeof(*byte_range));
			pdf_signature_widget_byte_range(ctx, doc, widget, byte_range);
		}

		contents_len = pdf_signature_widget_contents(ctx, doc, widget, &contents);
		if (byte_range && contents)
		{
			res = verify_sig(ctx, doc->file, contents, contents_len, byte_range, byte_range_len, ebuf, ebufsize);
			if (res)
				res = verify_cert(ctx, contents, contents_len, ebuf, ebufsize);
		}
		else
		{
			res = 0;
			fz_strlcpy(ebuf, "Not signed", ebufsize);
		}
	}
	fz_always(ctx)
	{
		fz_free(ctx, byte_range);
	}
	fz_catch(ctx)
	{
		res = 0;
		fz_strlcpy(ebuf, fz_caught_message(ctx), ebufsize);
	}

	if (ebufsize > 0)
		ebuf[ebufsize-1] = 0;

	return res;
}

void pdf_sign_signature(fz_context *ctx, pdf_document *doc, pdf_widget *widget, const char *sigfile, const char *password)
{
	pdf_signer *signer = pdf_read_pfx(ctx, sigfile, password);
	pdf_designated_name *dn = NULL;
	fz_buffer *fzbuf = NULL;

	fz_try(ctx)
	{
		const char *dn_str;
		pdf_obj *wobj = ((pdf_annot *)widget)->obj;
		fz_rect rect = fz_empty_rect;

		pdf_signature_set_value(ctx, doc, wobj, signer);

		pdf_to_rect(ctx, pdf_dict_get(ctx, wobj, PDF_NAME_Rect), &rect);
		/* Create an appearance stream only if the signature is intended to be visible */
		if (!fz_is_empty_rect(&rect))
		{
			dn = pdf_signer_designated_name(ctx, signer);
			fzbuf = fz_new_buffer(ctx, 256);
			if (!dn->cn)
				fz_throw(ctx, FZ_ERROR_GENERIC, "Certificate has no common name");

			fz_append_printf(ctx, fzbuf, "cn=%s", dn->cn);

			if (dn->o)
				fz_append_printf(ctx, fzbuf, ", o=%s", dn->o);

			if (dn->ou)
				fz_append_printf(ctx, fzbuf, ", ou=%s", dn->ou);

			if (dn->email)
				fz_append_printf(ctx, fzbuf, ", email=%s", dn->email);

			if (dn->c)
				fz_append_printf(ctx, fzbuf, ", c=%s", dn->c);

			dn_str = fz_string_from_buffer(ctx, fzbuf);
			pdf_set_signature_appearance(ctx, doc, (pdf_annot *)widget, dn->cn, dn_str, NULL);
		}
	}
	fz_always(ctx)
	{
		pdf_drop_signer(ctx, signer);
		pdf_drop_designated_name(ctx, dn);
		fz_drop_buffer(ctx, fzbuf);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}
}

int pdf_signatures_supported(fz_context *ctx)
{
	return 1;
}

#else /* HAVE_LIBCRYPTO */

int pdf_check_signature(fz_context *ctx, pdf_document *doc, pdf_widget *widget, char *ebuf, int ebufsize)
{
	fz_strlcpy(ebuf, "This version of MuPDF was built without signature support", ebufsize);
	return 0;
}

void pdf_sign_signature(fz_context *ctx, pdf_document *doc, pdf_widget *widget, const char *sigfile, const char *password)
{
}

pdf_signer *pdf_keep_signer(fz_context *ctx, pdf_signer *signer)
{
	return NULL;
}

void pdf_drop_signer(fz_context *ctx, pdf_signer *signer)
{
}

void pdf_write_digest(fz_context *ctx, fz_output *out, pdf_obj *byte_range, int digest_offset, int digest_length, pdf_signer *signer)
{
}

int pdf_signatures_supported(fz_context *ctx)
{
	return 0;
}

#endif /* HAVE_LIBCRYPTO */
