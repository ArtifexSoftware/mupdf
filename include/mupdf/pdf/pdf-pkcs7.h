#ifndef MUPDF_PDF_PKCS7_H
#define MUPDF_PDF_PKCS7_H

typedef enum
{
	SignatureError_Okay,
	SignatureError_NoSignatures,
	SignatureError_NoCertificate,
	SignatureError_DocumentChanged,
	SignatureError_SelfSigned,
	SignatureError_SelfSignedInChain,
	SignatureError_NotTrusted,
	SignatureError_Unknown
} SignatureError;

typedef struct pdf_pkcs7_designated_name_s
{
	char *cn;
	char *o;
	char *ou;
	char *email;
	char *c;
}
pdf_pkcs7_designated_name;

/* Check a signature's digest against ranges of bytes drawn from a stream */
SignatureError pdf_pkcs7_check_digest(fz_context *ctx, fz_stream *stm, char *sig, int sig_len);

/* Check a singature's certificate is trusted */
SignatureError pdf_pkcs7_check_certificate(char *sig, int sig_len);

/* Obtain the designated name information from signature's certificate */
pdf_pkcs7_designated_name *pdf_cert_designated_name(fz_context *ctx, char *sig, int sig_len);

/* Free the resources associated with designated name information */
void pdf_pkcs7_drop_designated_name(fz_context *ctx, pdf_pkcs7_designated_name *dn);

/* Read the certificate and private key from a pfx file, holding it as an opaque structure */
pdf_pkcs7_signer *pdf_pkcs7_read_pfx(fz_context *ctx, const char *pfile, const char *pw);

/* Increment the reference count for a signer object */
pdf_pkcs7_signer *pdf_pkcs7_keep_signer(fz_context *ctx, pdf_pkcs7_signer *signer);

/* Drop a reference for a signer object */
void pdf_pkcs7_drop_signer(fz_context *ctx, pdf_pkcs7_signer *signer);

/* Obtain the designated name information from a signer object */
pdf_pkcs7_designated_name *pdf_pkcs7_signer_designated_name(fz_context *ctx, pdf_pkcs7_signer *signer);

/* Create a signature based on ranges of bytes drawn from a steam */
int pdf_pkcs7_create_digest(fz_context *ctx, fz_stream *in, pdf_pkcs7_signer *signer, unsigned char *digest, int *digest_len);

/* Report whether pkcs7 is supported in the current build */
int pdf_pkcs7_supported(fz_context *ctx);

#endif
