#include "mupdf/fitz.h"
#include "mupdf/pdf.h"
#include "../fitz/fitz-imp.h"

#include <string.h>


static void pdf_print_designated_name(pdf_pkcs7_designated_name *name, char *buf, int buflen)
{
	int i, n;
	const char *part[] = {
		"/CN=", name->cn,
		"/O=", name->o,
		"/OU=", name->ou,
		"/emailAddress=", name->email,
		"/C=", name->c};

	if (buflen)
		buf[0] = 0;

	n = sizeof(part)/sizeof(*part);
	for (i = 0; i < n; i++)
		if (part[i])
			fz_strlcat(buf, part[i], buflen);
}

void pdf_write_digest(fz_context *ctx, fz_output *out, pdf_obj *byte_range, int hexdigest_offset, int hexdigest_length, pdf_pkcs7_signer *signer)
{
	fz_stream *in = NULL;
	fz_range *brange = NULL;
	int brange_len = pdf_array_len(ctx, byte_range)/2;
	unsigned char *digest = NULL;
	int digest_len;

	fz_var(in);
	fz_var(brange);

	if (hexdigest_length < 4)
		fz_throw(ctx, FZ_ERROR_GENERIC, "Bad parameters to pdf_write_digest");

	fz_try(ctx)
	{
		int i, res;

		brange = fz_calloc(ctx, brange_len, sizeof(*brange));
		for (i = 0; i < brange_len; i++)
		{
			brange[i].offset = pdf_to_int(ctx, pdf_array_get(ctx, byte_range, 2*i));
			brange[i].len = pdf_to_int(ctx, pdf_array_get(ctx, byte_range, 2*i+1));
		}

		in = fz_open_null_n(ctx, fz_stream_from_output(ctx, out), brange, brange_len);

		digest_len = (hexdigest_length - 2) / 2;
		digest = fz_malloc(ctx, digest_len);
		res = pdf_pkcs7_create_digest(ctx, in, signer, digest, &digest_len);
		if (!res)
			fz_throw(ctx, FZ_ERROR_GENERIC, "pdf_pkcs7_create_digest failed");

		fz_drop_stream(ctx, in);
		in = NULL;

		fz_seek_output(ctx, out, hexdigest_offset+1, SEEK_SET);

		for (i = 0; i < digest_len; i++)
			fz_write_printf(ctx, out, "%02x", digest[i]);
	}
	fz_always(ctx)
	{
		fz_free(ctx, digest);
		fz_free(ctx, brange);
		fz_drop_stream(ctx, in);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}
}

int pdf_check_signature(fz_context *ctx, pdf_document *doc, pdf_widget *widget, char *ebuf, int ebufsize)
{
	fz_stream *bytes = NULL;
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

	fz_var(bytes);
	fz_var(res);
	fz_try(ctx)
	{
		contents_len = pdf_signature_widget_contents(ctx, doc, widget, &contents);
		if (contents)
		{
			SignatureError err;

			bytes = pdf_signature_widget_hash_bytes(ctx, doc, widget);
			err = pdf_pkcs7_check_digest(ctx, bytes, contents, contents_len);
			if (err == SignatureError_Okay)
				err = pdf_pkcs7_check_certificate(contents, contents_len);
			switch (err)
			{
			case SignatureError_Okay:
				ebuf[0] = 0;
				res = 1;
				break;
			case SignatureError_NoSignatures:
				fz_strlcpy(ebuf, "No signatures", ebufsize);
				break;
			case SignatureError_NoCertificate:
				fz_strlcpy(ebuf, "No certificate", ebufsize);
				break;
			case SignatureError_DocumentChanged:
				fz_strlcpy(ebuf, "Document changed since signing", ebufsize);
				break;
			case SignatureError_SelfSigned:
				fz_strlcpy(ebuf, "Self-signed certificate", ebufsize);
				break;
			case SignatureError_SelfSignedInChain:
				fz_strlcpy(ebuf, "Self-signed certificate in chain", ebufsize);
				break;
			case SignatureError_NotTrusted:
				fz_strlcpy(ebuf, "Certificate not trusted", ebufsize);
				break;
			default:
			case SignatureError_Unknown:
				fz_strlcpy(ebuf, "Unknown error", ebufsize);
				break;
			}

			switch (err)
			{
			case SignatureError_SelfSigned:
			case SignatureError_SelfSignedInChain:
			case SignatureError_NotTrusted:
				{
					pdf_pkcs7_designated_name *name = pdf_cert_designated_name(ctx, contents, contents_len);
					if (name)
					{
						int len;

						fz_strlcat(ebuf, ": ", ebufsize);
						len = strlen(ebuf);
						pdf_print_designated_name(name, ebuf + len, ebufsize - len);
						pdf_pkcs7_drop_designated_name(ctx, name);
					}
				}
				break;
			default:
				break;
			}
		}
		else
		{
			res = 0;
			fz_strlcpy(ebuf, "Not signed", ebufsize);
		}
	}
	fz_always(ctx)
	{
		fz_drop_stream(ctx, bytes);
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
	pdf_pkcs7_signer *signer = pdf_pkcs7_read_pfx(ctx, sigfile, password);
	pdf_pkcs7_designated_name *dn = NULL;
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
			dn = pdf_pkcs7_signer_designated_name(ctx, signer);
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
		pdf_pkcs7_drop_signer(ctx, signer);
		pdf_pkcs7_drop_designated_name(ctx, dn);
		fz_drop_buffer(ctx, fzbuf);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}
}

int pdf_signatures_supported(fz_context *ctx)
{
	return pdf_pkcs7_supported(ctx);
}
